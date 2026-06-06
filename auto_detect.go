package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
)

var (
	qqAppIdPattern = regexp.MustCompile(`QQApp[Ii]d/([0-9]+)`)
	cachedAppInfo  AppInfoResponse
)

type autoDetectResult struct {
	Offset   uint64
	AppInfo  AppInfoResponse
	AppIDSrc string
	Errors   []string
}

// runAutoDetect 并行自动检测 offset 与 AppInfo
func runAutoDetect(cfg *Config, wrapperPath, qqAppDir string) autoDetectResult {
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		result autoDetectResult
	)

	appendErr := func(msg string) {
		mu.Lock()
		result.Errors = append(result.Errors, msg)
		mu.Unlock()
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		if cfg.Offset != "" && !cfg.OffsetAuto {
			return
		}
		offset, err := resolveSignOffset(cfg, wrapperPath)
		if err != nil {
			appendErr("offset: " + err.Error())
			return
		}
		mu.Lock()
		result.Offset = offset
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		info, src, err := resolveAppInfoAuto(cfg, qqAppDir, wrapperPath)
		if err != nil {
			appendErr("appinfo: " + err.Error())
			return
		}
		mu.Lock()
		result.AppInfo = info
		result.AppIDSrc = src
		mu.Unlock()
	}()

	wg.Wait()
	return result
}

func resolveAppInfoAuto(cfg *Config, qqAppDir, wrapperPath string) (AppInfoResponse, string, error) {
	if qqAppDir == "" {
		qqAppDir = filepath.Dir(wrapperPath)
	}
	if qqAppDir == "" {
		qqAppDir = detectQQAppDir()
	}

	version := cfg.Version
	if version == "" {
		version = readPackageVersion(qqAppDir)
	}
	if version == "" {
		version = readPackageVersion(filepath.Dir(wrapperPath))
	}

	appID, src, err := extractQQAppID(qqAppDir)
	if err == nil && appID > 0 {
		return buildAppInfoFromParts(version, appID), src, nil
	}

	appinfoPath := filepath.Join(filepath.Dir(wrapperPath), "appinfo.json")
	if fileExists(appinfoPath) {
		data, readErr := os.ReadFile(appinfoPath)
		if readErr == nil {
			var info AppInfoResponse
			if json.Unmarshal(data, &info) == nil && info.CurrentVersion != "" {
				return info, "appinfo.json", nil
			}
		}
	}

	if err != nil {
		return AppInfoResponse{}, "", err
	}
	return buildAppInfoFromParts(version, 0), "default", nil
}

func readPackageVersion(qqAppDir string) string {
	if qqAppDir == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(qqAppDir, "package.json"))
	if err != nil {
		return ""
	}
	var pkg PackageJSON
	if json.Unmarshal(data, &pkg) != nil {
		return ""
	}
	return pkg.Version
}

func extractQQAppID(qqAppDir string) (int64, string, error) {
	if qqAppDir == "" {
		return 0, "", fmt.Errorf("未找到 QQ resources/app 目录")
	}
	candidates := []string{
		filepath.Join(qqAppDir, "major.node"),
		filepath.Join(qqAppDir, "wrapper.node"),
	}
	for _, path := range candidates {
		if !fileExists(path) {
			continue
		}
		id, err := parseQQAppIDFromFile(path)
		if err == nil && id > 0 {
			return id, filepath.Base(path), nil
		}
	}
	// 回退 package.json linux appid
	if data, err := os.ReadFile(filepath.Join(qqAppDir, "package.json")); err == nil {
		var raw map[string]interface{}
		if json.Unmarshal(data, &raw) == nil {
			if appid, ok := raw["appid"].(map[string]interface{}); ok {
				if linux, ok := appid["linux"].(string); ok {
					if id, err := strconv.ParseInt(linux, 10, 64); err == nil {
						return id, "package.json", nil
					}
				}
			}
		}
	}
	return 0, "", fmt.Errorf("未在 major.node 中找到 QQAppId/ 且 package.json 无 linux appid")
}

func parseQQAppIDFromFile(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, needle := range [][]byte{[]byte("QQAppId/"), []byte("QQAppid/")} {
		idx := bytes.Index(data, needle)
		if idx < 0 {
			continue
		}
		start := idx + len(needle)
		end := start
		for end < len(data) && data[end] >= '0' && data[end] <= '9' {
			end++
		}
		if end == start {
			continue
		}
		return strconv.ParseInt(string(data[start:end]), 10, 64)
	}
	m := qqAppIdPattern.FindSubmatch(data)
	if len(m) < 2 {
		return 0, fmt.Errorf("未找到 QQAppId/ 字符串: %s", path)
	}
	return strconv.ParseInt(string(m[1]), 10, 64)
}

func buildAppInfoFromParts(version string, linuxAppID int64) AppInfoResponse {
	if version == "" {
		version = "0.0.0-0"
	}
	clientVer := parseAppClientVersion(version)
	if clientVer == 0 {
		clientVer = int(linuxAppID % 1000000)
	}
	return AppInfoResponse{
		Os:             "Linux",
		VendorOs:       "linux",
		Kernel:         "Linux",
		Qua:            "0",
		CurrentVersion: version,
		PtVersion:      "2.0.0",
		SsoVersion:     19,
		PackageName:    "com.tencent.qq",
		WtLoginSdk:       "nt.wtlogin.0.0.1",
		SdkInfo: SdkInfo{
			SdkBuildTime: 0,
			SdkVersion:   "0",
			MiscBitMap:   32764,
			SubSigMap:    0,
			MainSigMap:   169742560,
		},
		AppId:            1600001615,
		AppIdQrCode:      linuxAppID,
		SubAppId:         linuxAppID,
		AppClientVersion: clientVer,
		NTLoginType:      1,
	}
}

func applyAutoDetectToConfig(cfg *Config, detected autoDetectResult) {
	if detected.Offset > 0 && (cfg.Offset == "" || cfg.OffsetAuto) {
		cfg.Offset = fmt.Sprintf("0x%X", detected.Offset)
		log.Printf("Auto-detected sign offset: %s", cfg.Offset)
	}
	if detected.AppInfo.CurrentVersion != "" || detected.AppInfo.SubAppId > 0 {
		cachedAppInfo = detected.AppInfo
		if cfg.Version == "" && detected.AppInfo.CurrentVersion != "" {
			cfg.Version = detected.AppInfo.CurrentVersion
		}
	}
	if len(detected.Errors) > 0 {
		for _, e := range detected.Errors {
			log.Printf("Auto-detect warning: %s", e)
		}
	}
	if detected.AppIDSrc != "" {
		log.Printf("Auto-detected AppInfo from %s (SubAppId=%d, version=%s)",
			detected.AppIDSrc, detected.AppInfo.SubAppId, detected.AppInfo.CurrentVersion)
	}
}

// runStartupAutoDetect 启动时并行自动检测 offset 与 AppInfo（未配置时生效）
func runStartupAutoDetect(qqAppDirParam, wrapperDir string) {
	qqAppDir := qqAppDirParam
	if qqAppDir == "" {
		qqAppDir = config.Env.QQAppDir
	}
	if qqAppDir == "" {
		qqAppDir = detectQQAppDir()
	}
	if qqAppDir == "" && wrapperDir != "" {
		qqAppDir = wrapperDir
	}

	wp := wrapperPath
	if wp == "" {
		wp = filepath.Join(wrapperDir, "wrapper.node")
	}
	if !fileExists(wp) {
		log.Printf("Auto-detect skipped: wrapper not found at %s", wp)
		return
	}

	log.Printf("Auto-detect: parallel scan offset + appinfo (qqAppDir=%s)", qqAppDir)
	detected := runAutoDetect(config, wp, qqAppDir)
	applyAutoDetectToConfig(config, detected)
}

func currentQQVersion() AppInfoResponse {
	if cachedAppInfo.CurrentVersion != "" || cachedAppInfo.SubAppId > 0 {
		return cachedAppInfo
	}
	if config != nil && config.Version != "" {
		return buildAppInfoFromParts(config.Version, 0)
	}
	return buildAppInfoFromParts("0.0.0-0", 0)
}
