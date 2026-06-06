//go:build linux

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	attachQQPID       int
	attachWrapperBase uint64
)

func defaultAttachSettings() AttachSettings {
	return AttachSettings{
		BridgeSocket:     "/tmp/nekogel_sign_bridge.sock",
		QQProcessNames:   []string{"qq", "QQ", "linuxqq", "qq-exe"},
		WaitReadySeconds: 120,
	}
}

func initAttachMode(cfg *Config) error {
	attach := cfg.Attach
	if attach.BridgeSocket == "" {
		attach.BridgeSocket = defaultAttachSettings().BridgeSocket
	}
	if len(attach.QQProcessNames) == 0 {
		attach.QQProcessNames = defaultAttachSettings().QQProcessNames
	}
	if attach.WaitReadySeconds <= 0 {
		attach.WaitReadySeconds = 120
	}
	cfg.Attach = attach
	attachBridgeSocket = attach.BridgeSocket

	pid, procPath, err := findQQProcess(attach.QQProcessNames)
	if err != nil {
		log.Printf("WARNING: QQ process not found yet: %v", err)
	} else {
		attachQQPID = pid
		base, wrapperFile, mapErr := getWrapperMappingFromPID(pid)
		if mapErr != nil {
			log.Printf("WARNING: wrapper.node not mapped in QQ yet (pid=%d): %v", pid, mapErr)
		} else {
			attachWrapperBase = base
			if wrapperFile != "" {
				wrapperPath = wrapperFile
			}
			log.Printf("Attach mode: QQ pid=%d exe=%s wrapper_base=0x%X wrapper=%s", pid, procPath, base, wrapperPath)
		}
	}

	deadline := time.Now().Add(time.Duration(attach.WaitReadySeconds) * time.Second)
	for {
		if bridgeReady() {
			log.Printf("Attach bridge ready at %s", attachBridgeSocket)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf(
				"attach bridge not ready at %s; start QQ with: LD_PRELOAD=./sign_bridge/libsign_bridge.so SIGN_OFFSET=%s SIGN_BRIDGE_SOCK=%s /opt/QQ/qq",
				attachBridgeSocket, cfg.Offset, attachBridgeSocket,
			)
		}
		debugPrint("Waiting for attach bridge...")
		time.Sleep(time.Second)
	}
}

func bridgeReady() bool {
	conn, err := net.DialTimeout("unix", attachBridgeSocket, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func findQQProcess(names []string) (int, string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, "", err
	}
	nameSet := make(map[string]struct{}, len(names))
	for _, n := range names {
		nameSet[n] = struct{}{}
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		exePath := filepath.Join("/proc", entry.Name(), "exe")
		target, err := os.Readlink(exePath)
		if err != nil {
			continue
		}
		base := filepath.Base(target)
		if _, ok := nameSet[base]; ok {
			return pid, target, nil
		}
	}
	return 0, "", fmt.Errorf("no QQ process found in /proc (names=%v)", names)
}

func getWrapperMappingFromPID(pid int) (uint64, string, error) {
	mapsPath := filepath.Join("/proc", strconv.Itoa(pid), "maps")
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return 0, "", err
	}

	var bestBase uint64
	var bestPath string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "wrapper.node") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		rangePart := strings.Split(fields[0], "-")
		if len(rangePart) != 2 {
			continue
		}
		base, err := strconv.ParseUint(rangePart[0], 16, 64)
		if err != nil {
			continue
		}
		path := ""
		if len(fields) >= 6 {
			path = fields[len(fields)-1]
		}
		if strings.Contains(line, "r-xp") || strings.Contains(line, "r--p") {
			if base > bestBase || bestPath == "" {
				bestBase = base
				bestPath = path
			}
		}
	}

	if bestBase == 0 {
		return 0, "", fmt.Errorf("wrapper.node mapping not found in /proc/%d/maps", pid)
	}
	return bestBase, bestPath, nil
}

func signViaAttachBridge(cmd, srcHex string, seq int) (*Response, error) {
	conn, err := net.DialTimeout("unix", attachBridgeSocket, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect attach bridge failed: %w", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("%s\t%d\t%s\n", cmd, seq, strings.ToUpper(srcHex))
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, fmt.Errorf("write attach bridge request failed: %w", err)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read attach bridge response failed: %w", err)
	}
	line = strings.TrimSpace(line)
	parts := strings.Split(line, "\t")
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid attach bridge response")
	}
	if parts[0] == "ERR" {
		msg := "attach bridge error"
		if len(parts) > 1 {
			msg = parts[1]
		}
		return nil, fmt.Errorf("%s", msg)
	}
	if parts[0] != "OK" || len(parts) < 4 {
		return nil, fmt.Errorf("invalid attach bridge response: %s", line)
	}
	return &Response{
		Value: ResponseValue{
			Token: strings.ToUpper(parts[1]),
			Extra: strings.ToUpper(parts[2]),
			Sign:  strings.ToUpper(parts[3]),
		},
	}, nil
}

func refreshAttachStatus() map[string]interface{} {
	status := map[string]interface{}{
		"mode":           signMode,
		"bridge_socket":  attachBridgeSocket,
		"bridge_ready":   bridgeReady(),
		"qq_pid":         attachQQPID,
		"wrapper_base":   fmt.Sprintf("0x%X", attachWrapperBase),
		"wrapper_path":   wrapperPath,
	}

	if attachQQPID == 0 {
		if pid, exe, err := findQQProcess(config.Attach.QQProcessNames); err == nil {
			attachQQPID = pid
			status["qq_pid"] = pid
			status["qq_exe"] = exe
		}
	}
	if attachQQPID != 0 {
		if base, path, err := getWrapperMappingFromPID(attachQQPID); err == nil {
			attachWrapperBase = base
			status["wrapper_base"] = fmt.Sprintf("0x%X", base)
			if path != "" {
				wrapperPath = path
				status["wrapper_path"] = path
			}
		}
	}
	return status
}

func handleAttachStatus(c *gin.Context) {
	c.JSON(200, refreshAttachStatus())
}
