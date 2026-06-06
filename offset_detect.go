package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
)

// sub_5BD3EA1 签名入口（IDA）机器码特征：
//   push rbp/r15/r14/r13/r12/rbx; sub rsp,138h; mov [rsp+50h],r8; mov [rsp+4],ecx
//   mov ebp,edx; mov rbx,rsi; mov [rsp+48h],rdi; fs:28h canary
//   ... call _dladdr; lea rbx,[rsp+0D2h]; mov eax,12DEA1A0h; xor r12d,r12d ...

// defaultSignSignatures 按优先级排列；更长特征优先，减少误匹配
var defaultSignSignatures = []string{
	// 64B：至 lea rsi,[rsp+68h] + mov [rsp+10h],rsi
	"554157415641554154534881ec380100004c89442450894c240489d54889f348897c244864488b0425280000004889842430010000488d7424684889742410",
	// 48B：至 fs:28h canary 保存
	"554157415641554154534881ec380100004c89442450894c240489d54889f348897c244864488b042528000000",
	// 24B：经典函数序言（旧配置兼容）
	"554157415641554154534881ec380100004c89442450894c",
}

// signFuncAnchors 相对函数入口的锚点；?? 为通配字节（如 call 的 rel32）
var signFuncAnchors = []struct {
	Offset int
	Hex    string
}{
	{0x3F, "488b442410"},                         // mov rax, [rsp+10h]
	{0x44, "488bbc2468010000"},                   // mov rdi, [rsp+168h]（_dladdr 参数）
	{0x4C, "e8????????89442408"},                 // call _dladdr; mov [rsp+8], eax
	{0x5F, "488d9c24d2000000"},                   // lea rbx, [rsp+0D2h]
	{0x6C, "4531e44c8dac2488000000"},             // xor r12d,r12d; lea r13,[rsp+88h]
	{0x77, "41bff42715eb41becffde0c3"},           // mov r15d,...; mov r14d,...
}

// resolveSignOffset 解析或自动检测签名函数偏移
func resolveSignOffset(cfg *Config, wrapperPath string) (uint64, error) {
	if cfg.Offset != "" && !cfg.OffsetAuto {
		var offset uint64
		n, err := fmt.Sscanf(strings.TrimSpace(cfg.Offset), "0x%x", &offset)
		if err != nil || n != 1 {
			return 0, fmt.Errorf("解析 offset 失败: %s", cfg.Offset)
		}
		return offset, nil
	}

	signatures := cfg.OffsetSignatures
	if len(signatures) == 0 {
		signatures = defaultSignSignatures
	}
	offset, sigUsed, err := detectOffsetFromWrapper(wrapperPath, signatures)
	if err != nil {
		return 0, err
	}
	log.Printf("Auto-detected sign offset: 0x%X (signature=%s)", offset, sigUsed)
	return offset, nil
}

func detectOffsetFromWrapper(wrapperPath string, signatureHexList []string) (uint64, string, error) {
	data, err := os.ReadFile(wrapperPath)
	if err != nil {
		return 0, "", fmt.Errorf("读取 wrapper.node 失败: %w", err)
	}
	if len(data) < 64 || data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return 0, "", fmt.Errorf("wrapper.node 不是有效 ELF 文件")
	}

	for _, sigHex := range signatureHexList {
		sigHex = strings.TrimSpace(sigHex)
		if sigHex == "" {
			continue
		}
		pattern, mask, err := parseHexPattern(sigHex)
		if err != nil {
			return 0, "", fmt.Errorf("offset_signature 非法: %w", err)
		}
		if len(pattern) < 16 {
			return 0, "", fmt.Errorf("offset_signature 太短，建议至少 24 字节")
		}

		candidates := findPatternOffsets(data, pattern, mask)
		for _, fileOff := range candidates {
			if !verifySignFuncAnchors(data, fileOff) {
				continue
			}
			va, err := elfFileOffsetToVA(data, fileOff)
			if err != nil {
				continue
			}
			label := sigHex
			if len(label) > 32 {
				label = label[:32] + "..."
			}
			return va, label, nil
		}
	}

	return 0, "", fmt.Errorf("未在 wrapper.node 中匹配到 sub_5BD3EA1 特征，请手动配置 offset 或更新 offset_signatures")
}

func verifySignFuncAnchors(data []byte, entryOff int) bool {
	for _, anchor := range signFuncAnchors {
		pat, mask, err := parseHexPattern(anchor.Hex)
		if err != nil {
			return false
		}
		start := entryOff + anchor.Offset
		end := start + len(pat)
		if start < 0 || end > len(data) {
			return false
		}
		if !matchPattern(data[start:end], pat, mask) {
			return false
		}
	}
	return true
}

func parseHexPattern(hexStr string) ([]byte, []bool, error) {
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ToLower(hexStr)
	if len(hexStr)%2 != 0 {
		return nil, nil, fmt.Errorf("hex 长度必须为偶数")
	}

	pattern := make([]byte, len(hexStr)/2)
	mask := make([]bool, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		tok := hexStr[i : i+2]
		if tok == "??" || tok == "?" {
			mask[i/2] = true
			continue
		}
		b, err := hex.DecodeString(tok)
		if err != nil {
			return nil, nil, err
		}
		pattern[i/2] = b[0]
	}
	return pattern, mask, nil
}

func findPatternOffsets(data, pattern []byte, mask []bool) []int {
	hasWildcard := false
	for _, m := range mask {
		if m {
			hasWildcard = true
			break
		}
	}
	if !hasWildcard {
		var hits []int
		idx := 0
		for {
			i := bytes.Index(data[idx:], pattern)
			if i < 0 {
				break
			}
			pos := idx + i
			hits = append(hits, pos)
			idx = pos + 1
		}
		return hits
	}

	var hits []int
	for off := 0; off <= len(data)-len(pattern); off++ {
		if matchPattern(data[off:off+len(pattern)], pattern, mask) {
			hits = append(hits, off)
		}
	}
	return hits
}

func matchPattern(data, pattern []byte, mask []bool) bool {
	if len(data) != len(pattern) {
		return false
	}
	for i := range pattern {
		if mask[i] {
			continue
		}
		if data[i] != pattern[i] {
			return false
		}
	}
	return true
}

// 保留供测试/调试：在二进制中扫描固定字节序列（无通配符）
func findUniqueBytes(data []byte, sig []byte) []int {
	var hits []int
	idx := 0
	for {
		i := bytes.Index(data[idx:], sig)
		if i < 0 {
			break
		}
		pos := idx + i
		hits = append(hits, pos)
		idx = pos + 1
	}
	return hits
}

func elfFileOffsetToVA(elfData []byte, fileOffset int) (uint64, error) {
	if fileOffset < 0 || fileOffset >= len(elfData) {
		return 0, fmt.Errorf("file offset 越界")
	}
	if len(elfData) < 64 {
		return 0, fmt.Errorf("ELF 头过短")
	}
	eiClass := elfData[4]
	if eiClass != 2 {
		return 0, fmt.Errorf("仅支持 ELF64")
	}

	ePhoff := leUint64(elfData[32:40])
	ePhentsize := leUint16(elfData[54:56])
	ePhnum := leUint16(elfData[56:58])

	for i := 0; i < int(ePhnum); i++ {
		off := int(ePhoff) + i*int(ePhentsize)
		if off+56 > len(elfData) {
			break
		}
		ph := elfData[off:]
		pType := leUint32(ph[0:4])
		if pType != 1 { // PT_LOAD
			continue
		}
		pOffset := leUint64(ph[8:16])
		pVaddr := leUint64(ph[16:24])
		pFilesz := leUint64(ph[32:40])
		if uint64(fileOffset) >= pOffset && uint64(fileOffset) < pOffset+pFilesz {
			return pVaddr + uint64(fileOffset) - pOffset, nil
		}
	}
	return 0, fmt.Errorf("无法将 file offset 0x%X 映射到虚拟地址", fileOffset)
}

func leUint16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

func leUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func leUint64(b []byte) uint64 {
	return uint64(leUint32(b[0:4])) | uint64(leUint32(b[4:8]))<<32
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
