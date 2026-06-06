package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
)

/*
#cgo CFLAGS: -fvisibility=default
#cgo LDFLAGS: -ldl -Wl,--export-dynamic
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <link.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

// 内置的符号定义
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025 Moew72 <Moew72@proton.me>
__attribute__((visibility("default"))) void qq_magic_napi_register(void* unused) { }

// 定义签名函数指针类型
typedef long long (*sign_func)(char*, unsigned char*, int, int, unsigned char*);

// 全局变量声明
static char** libs = NULL;              // 需要预加载的库列表
static unsigned long long offset = 0;   // 签名函数在内存中的偏移量
static sign_func sign = NULL;           // 签名函数指针
static char* wrapper_dir = NULL;        // wrapper.node 文件所在目录
static char* wrapper_path = NULL;       // wrapper.node 文件完整路径
static unsigned long long module_base = 0;  // 模块基地址
static void* module = NULL;             // 加载的模块句柄
static int debug_mode = 0;              // 调试模式标志

// 设置调试模式
void set_debug_mode_go(int mode) {
    debug_mode = mode;
}

// 调试打印宏
#define DEBUG_PRINT(...) do { \
    if (debug_mode) { \
        fprintf(stderr, __VA_ARGS__); \
    } \
} while(0)

// 回调函数，用于遍历已加载的共享对象并找到 wrapper.node
int callback(struct dl_phdr_info* info, size_t size, void* data) {
	DEBUG_PRINT("DEBUG: dl_iterate_phdr callback called\n");
	if (info && info->dlpi_name) {
		DEBUG_PRINT("DEBUG: Checking module: %s\n", info->dlpi_name);
		if (strstr(info->dlpi_name, "wrapper.node")) {
			module_base = info->dlpi_addr;  // 记录找到的模块基地址
			DEBUG_PRINT("DEBUG: Found wrapper.node at base address: 0x%llx\n", (unsigned long long)module_base);
			return 1;  // 找到后返回1停止遍历
		}
	}
	return 0;  // 继续遍历
}

// 设置 wrapper.node 文件所在目录
void set_wrapper_path_go(const char* dir) {
	DEBUG_PRINT("DEBUG: set_wrapper_path_go called with dir: %s\n", dir ? dir : "NULL");
	// 释放之前分配的内存
	if (wrapper_dir) {
		DEBUG_PRINT("DEBUG: Freeing previous wrapper_dir\n");
		free(wrapper_dir);
		wrapper_dir = NULL;
	}
	
	// 复制目录路径
	if (dir) {
		size_t len = strlen(dir);
		if (len > 0) {
			wrapper_dir = (char*)malloc(len + 1);
			if (wrapper_dir) {
				strcpy(wrapper_dir, dir);
				DEBUG_PRINT("DEBUG: Set wrapper directory: %s\n", wrapper_dir);
			} else {
				DEBUG_PRINT("ERROR: Failed to allocate memory for wrapper_dir\n");
			}
		} else {
			DEBUG_PRINT("DEBUG: dir is empty\n");
		}
	} else {
		DEBUG_PRINT("DEBUG: dir is NULL\n");
	}
}

// 设置需要预加载的库列表
void set_libs_go(char** new_libs) {
	DEBUG_PRINT("DEBUG: set_libs_go called\n");
	libs = new_libs;
}

// 设置签名函数的内存偏移量
void set_offset_go(unsigned long long new_offset) {
	DEBUG_PRINT("DEBUG: set_offset_go called with offset: 0x%llx\n", new_offset);
	offset = new_offset;
	DEBUG_PRINT("DEBUG: Set offset: 0x%llx\n", offset);
}

// 安全的字符串连接函数
char* safe_strcat(const char* str1, const char* str2, const char* str3) {
	DEBUG_PRINT("DEBUG: safe_strcat called with str1: %s, str2: %s, str3: %s\n", 
		str1 ? str1 : "NULL", str2 ? str2 : "NULL", str3 ? str3 : "NULL");
		
	if (!str1 || !str2) {
		DEBUG_PRINT("DEBUG: safe_strcat received NULL pointer\n");
		return NULL;
	}
	
	size_t len1 = strlen(str1);
	size_t len2 = str3 ? strlen(str3) : 0;
	size_t len = len1 + strlen(str2) + len2 + 1; // +1 for null terminator
	
	DEBUG_PRINT("DEBUG: safe_strcat allocating %zu bytes\n", len);
	
	char* result = (char*)malloc(len);
	if (result) {
		if (str3) {
			snprintf(result, len, "%s%s%s", str1, str2, str3);
		} else {
			snprintf(result, len, "%s%s", str1, str2);
		}
		DEBUG_PRINT("DEBUG: safe_strcat result: %s\n", result);
	} else {
		DEBUG_PRINT("DEBUG: safe_strcat malloc failed\n");
	}
	return result;
}

// 加载签名模块
int load_module_go() {
	DEBUG_PRINT("DEBUG: Entering load_module_go\n");
	
	// 检查 wrapper 目录是否已设置
	if (!wrapper_dir) {
		DEBUG_PRINT("ERROR: wrapper_dir not set\n");
		return 1;  // 未设置返回错误
	}
	
	DEBUG_PRINT("DEBUG: wrapper_dir is set to: %s\n", wrapper_dir);
	
	// 检查目录是否存在
	if (access(wrapper_dir, F_OK) == -1) {
		DEBUG_PRINT("ERROR: wrapper directory does not exist: %s, errno: %d (%s)\n", 
			wrapper_dir, errno, strerror(errno));
		return 1;
	}

	// 释放之前分配的内存
	if (wrapper_path) {
		DEBUG_PRINT("DEBUG: Freeing previous wrapper_path\n");
		free(wrapper_path);
		wrapper_path = NULL;
	}

	// 构造 wrapper.node 文件的完整路径
	DEBUG_PRINT("DEBUG: Constructing wrapper path, dir length: %zu\n", strlen(wrapper_dir));
		
	if (wrapper_dir[strlen(wrapper_dir) - 1] == '/') {
		// 目录以 '/' 结尾
		DEBUG_PRINT("DEBUG: Directory ends with '/', constructing without additional slash\n");
		wrapper_path = safe_strcat(wrapper_dir, "wrapper.node", NULL);
	} else {
		// 目录不以 '/' 结尾
		DEBUG_PRINT("DEBUG: Directory does not end with '/', adding slash\n");
		wrapper_path = safe_strcat(wrapper_dir, "/wrapper.node", NULL);
	}

	// 检查内存分配是否成功
	if (!wrapper_path) {
		DEBUG_PRINT("ERROR: failed to allocate memory for wrapper_path\n");
		return 1;
	}
	
	DEBUG_PRINT("DEBUG: Constructed wrapper path: %s\n", wrapper_path);

	// 检查文件是否存在
	DEBUG_PRINT("DEBUG: Checking if file exists...\n");
	if (access(wrapper_path, F_OK) == -1) {
		DEBUG_PRINT("ERROR: wrapper.node file does not exist at path: %s, errno: %d (%s)\n", 
			wrapper_path, errno, strerror(errno));
		return 1;
	}
	DEBUG_PRINT("DEBUG: File exists, continuing...\n");
	
	// 检查文件大小
	struct stat st;
	if (stat(wrapper_path, &st) == 0) {
		DEBUG_PRINT("DEBUG: wrapper.node file size: %ld bytes\n", st.st_size);
		if (st.st_size == 0) {
			DEBUG_PRINT("ERROR: wrapper.node file is empty\n");
			return 1;
		}
	} else {
		DEBUG_PRINT("WARNING: Could not get file size: %s\n", strerror(errno));
	}

	// 预加载指定的库文件
	if (libs) {
		DEBUG_PRINT("DEBUG: Preloading libraries...\n");
		for (int i = 0; libs[i] != NULL; i++) {
			DEBUG_PRINT("DEBUG: Preloading library: %s\n", libs[i]);
			// 使用 RTLD_LAZY | RTLD_GLOBAL 方式加载库
			void *handle = dlopen(libs[i], RTLD_LAZY | RTLD_GLOBAL);
			if (!handle) {
				DEBUG_PRINT("ERROR: failed to load library %s: %s\n", libs[i], dlerror());
				// 加载失败则清理资源并返回错误
				return 1;
			}
			DEBUG_PRINT("DEBUG: Successfully loaded library: %s\n", libs[i]);
		}
	} else {
		DEBUG_PRINT("DEBUG: No libraries to preload\n");
	}
//neko
	// 加载 wrapper.node 模块
	DEBUG_PRINT("DEBUG: Loading wrapper.node module from: %s\n", wrapper_path);
	module = dlopen(wrapper_path, RTLD_LAZY);
	if (!module) {
		const char* error = dlerror();
		DEBUG_PRINT("ERROR: failed to load wrapper.node module: %s\n", error ? error : "unknown error");
		// 提供一些常见问题的解决建议
		if (error && strstr(error, "libX11-xcb")) {
			DEBUG_PRINT("SUGGESTION: Missing X11-XCB library. Try installing: sudo apt-get install libx11-xcb1\n");
		} else if (error && strstr(error, "undefined symbol: gnutls")) {
			DEBUG_PRINT("SUGGESTION: Missing GnuTLS library. Try installing: sudo apt-get install libgnutls30 libgnutls-dev\n");
		} else if (error && strstr(error, "cannot open shared object file")) {
			DEBUG_PRINT("SUGGESTION: Missing system library. Check dependencies with: ldd %s\n", wrapper_path);
		} else if (error && strstr(error, "undefined symbol: qq_magic_napi_register")) {
			DEBUG_PRINT("SUGGESTION: Missing required symbol. Make sure qq_magic_napi_register is exported.\n");
		}
		// 加载失败则清理资源并返回错误
		return 1;
	}
	
	DEBUG_PRINT("DEBUG: Successfully loaded wrapper.node module\n");

	// 遍历已加载的共享对象，找到 wrapper.node 模块的基地址
	module_base = 0;
	DEBUG_PRINT("DEBUG: Iterating through loaded modules to find wrapper.node...\n");
	int iterate_result = dl_iterate_phdr(callback, NULL);
	DEBUG_PRINT("DEBUG: dl_iterate_phdr returned: %d\n", iterate_result);

	// 检查是否成功找到模块基地址
	if (module_base == 0) {
		DEBUG_PRINT("ERROR: failed to find module base address for wrapper.node\n");
		dlclose(module);
		module = NULL;
		return 1;
	}

	// 计算签名函数的实际地址
	unsigned long long sign_addr = module_base + offset;
	DEBUG_PRINT("DEBUG: Calculated sign function address: 0x%llx (base: 0x%llx + offset: 0x%llx)\n", sign_addr, module_base, offset);
	
	// 检查计算出的地址是否合理
	if (sign_addr < 0x10000) {
		DEBUG_PRINT("ERROR: calculated sign function address seems invalid: 0x%llx\n", sign_addr);
		dlclose(module);
		module = NULL;
		return 1;
	}
	
	sign = (sign_func)(sign_addr);

	// 验证签名函数地址是否有效
	if (!sign) {
		DEBUG_PRINT("ERROR: sign function pointer is NULL\n");
		dlclose(module);
		module = NULL;
		return 1;
	}

	DEBUG_PRINT("DEBUG: Successfully initialized sign module\n");
	return 0;  // 成功返回0
}

// 调用签名函数执行签名操作
int sign_go(const char* cmd, const unsigned char* src, int src_len, int seq, unsigned char* output) {
	DEBUG_PRINT("DEBUG: sign_go called with cmd: %s, src_len: %d, seq: %d\n", cmd ? cmd : "NULL", src_len, seq);
	if (!sign) {
		DEBUG_PRINT("ERROR: sign function not initialized\n");
		return -1;  // 签名函数未初始化返回错误
	}
	int result = sign((char*)cmd, (unsigned char*)src, src_len, seq, output);
	DEBUG_PRINT("DEBUG: sign_go returned: %d\n", result);
	return result;
}

// 卸载签名模块并清理资源
void unload_module_go() {
	DEBUG_PRINT("DEBUG: unload_module_go called\n");
	if (module) {
		dlclose(module);    // 关闭模块
		module = NULL;
	}
	if (wrapper_dir) {
		free(wrapper_dir);  // 释放目录路径内存
		wrapper_dir = NULL;
	}
	if (wrapper_path) {
		free(wrapper_path); // 释放文件路径内存
		wrapper_path = NULL;
	}
	module_base = 0;      // 重置模块基地址
	sign = NULL;          // 重置签名函数指针
}
*/
import "C"

// AttachSettings QQ 进程 attach 模式配置
type AttachSettings struct {
	BridgeSocket     string   `toml:"bridge_socket"`
	QQProcessNames   []string `toml:"qq_process_names"`
	WaitReadySeconds int      `toml:"wait_ready_seconds"`
}

// EnvSettings wrapper.node 运行时环境补全配置（主要服务于 dlopen 模式）
type EnvSettings struct {
	AutoSetup       bool   `toml:"auto_setup"`        // 启动前自动补环境
	Display         string `toml:"display"`           // X11 DISPLAY
	DataPath        string `toml:"data_path"`         // QQ 数据目录，默认 ~/.config/QQ
	QQAppDir        string `toml:"qq_app_dir"`        // Linux QQ 的 resources/app 目录
	CopyFromQQ      bool   `toml:"copy_from_qq"`      // 从 qq_app_dir 复制缺失的运行文件
	SyncFromQQ      bool   `toml:"sync_from_qq"`      // 强制用 QQ 安装目录覆盖关键配置
	ChdirToWrapper  bool   `toml:"chdir_to_wrapper"`  // dlopen 前切到 wrapper 目录
	Timezone        string `toml:"timezone"`          // 时区，默认 Asia/Shanghai
}

// Config 配置结构体，用于解析 TOML 配置文件
type Config struct {
	Preloads     []string       `toml:"preloads"`      // 需要预加载的库文件列表
	Listen       string         `toml:"listen"`        // 服务器监听地址和端口
	Offset            string   `toml:"offset"`             // 签名函数偏移；留空且 offset_auto=true 时自动检测
	OffsetAuto        bool     `toml:"offset_auto"`        // 自动扫描 wrapper.node 特征定位签名函数
	OffsetSignatures  []string `toml:"offset_signatures"`  // 自定义特征 hex（优先于内置默认）
	Version      string         `toml:"version"`       // QQ 客户端版本号
	AdminKey     string         `toml:"admin_key"`     // 管理员密钥，用于 Token 管理
	TokenTimeout int            `toml:"token_timeout"` // Token 过期时间（秒）
	SignMode     string         `toml:"sign_mode"`     // dlopen 或 attach
	Env          EnvSettings    `toml:"env"`           // 运行时环境补全
	Attach       AttachSettings `toml:"attach"`        // QQ attach 模式
}

// ConfigEnvJSON wrapper 目录下的 config.env.json
type ConfigEnvJSON struct {
	EnableEnvConfig     bool   `json:"enableEnvConfig"`
	DefaultSamplingRate int    `json:"defautlSamplingRate"`
	IsTestEnv           bool   `json:"is_test_env"`
	IP                  string `json:"ip"`
	Port                int    `json:"port"`
	EnvID               string `json:"env_id"`
	Canary              string `json:"canary"`
}

// PackageJSON wrapper 目录下的 package.json（Linux QQ 资源目录常见文件）
type PackageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Qua     string `json:"qua"`
}

// ResponseValue 签名响应值结构体
type ResponseValue struct {
	Token string `json:"token"` // 签名令牌
	Extra string `json:"extra"` // 额外数据
	Sign  string `json:"sign"`  // 签名结果
}

// Response 签名响应结构体
type Response struct {
	Value ResponseValue `json:"value"` // 响应值
}

// SdkInfo SDK 信息结构体
type SdkInfo struct {
	SdkBuildTime int64  `json:"SdkBuildTime"` // SDK 构建时间
	SdkVersion   string `json:"SdkVersion"`   // SDK 版本
	MiscBitMap   int    `json:"MiscBitMap"`   // 杂项位图
	SubSigMap    int    `json:"SubSigMap"`    // 子签名映射
	MainSigMap   int    `json:"MainSigMap"`   // 主签名映射
}

// AppInfoResponse AppInfo 响应结构体 (新格式)
type AppInfoResponse struct {
	Os               string   `json:"Os"`               // 操作系统
	VendorOs         string   `json:"VendorOs"`         // 供应商操作系统
	Kernel           string   `json:"Kernel"`           // 内核信息
	Qua              string   `json:"Qua"`              // QUA 信息
	CurrentVersion   string   `json:"CurrentVersion"`   // 当前版本
	PtVersion        string   `json:"PtVersion"`        // PT 版本
	SsoVersion       int      `json:"SsoVersion"`       // SSO 版本
	PackageName      string   `json:"PackageName"`      // 包名
	WtLoginSdk       string   `json:"WtLoginSdk"`       // WT 登录 SDK
	SdkInfo          SdkInfo  `json:"SdkInfo"`          // SDK 信息
	AppId            int64    `json:"AppId"`            // 应用 ID
	AppIdQrCode      int64    `json:"AppIdQrCode"`      // QR 码应用 ID
	SubAppId         int64    `json:"SubAppId"`         // 子应用 ID
	AppClientVersion int      `json:"AppClientVersion"` // 应用客户端版本
	NTLoginType      int      `json:"NTLoginType"`      // NT 登录类型
}

// YanXiYuHomeResponse 首页响应（YanXiYu LinuxNT Sign）
type YanXiYuHomeResponse struct {
	Status      string            `json:"status"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Version     string            `json:"version"`
	Pages       map[string]string `json:"Pages"`
	Static      map[string]uint64 `json:"Static"`
	QQVersion   AppInfoResponse   `json:"QQVersion"`
}

// SignRequest 签名请求结构体
type SignRequest struct {
	Cmd string `json:"cmd" binding:"required"` // 命令
	Src string `json:"src" binding:"required"` // 源数据（十六进制字符串）
	Seq int    `json:"seq"`                    // 序列号
}

// Global variables 全局变量声明
var (
	config       *Config       // 配置信息
	wrapperPath  string        // wrapper.node 文件路径
	debugMode    bool          // 调试模式
	signMode           string // dlopen 或 attach
	attachBridgeSocket string
	runtimeEnvReport   map[string]interface{}
	preloadLibCSStrings []*C.char // 保持 preload 路径 C 字符串存活至进程结束
	preloadLibCArray    []*C.char // 含 NULL 终止，供 set_libs_go 使用
)

// main 主函数，程序入口点
func main() {
	var configPath string
	var wrapperPathParam string

	var qqAppDirParam string

	flag.StringVar(&configPath, "config", "sign.config.toml", "配置文件路径")
	flag.StringVar(&wrapperPathParam, "wrapper-path", "", "wrapper.node 文件路径")
	flag.StringVar(&qqAppDirParam, "qq-app-dir", "", "Linux QQ resources/app 目录，用于复制运行环境文件")
	flag.BoolVar(&debugMode, "debug", false, "启用调试模式")
	flag.Parse()

	if debugMode {
		log.Printf("=== SERVER STARTUP ===")
		log.Printf("Command line args - config: %s, wrapper-path: %s, debug: %v", configPath, wrapperPathParam, debugMode)
	}

	// 设置 C 代码中的调试模式
	if debugMode {
		C.set_debug_mode_go(1)
	} else {
		C.set_debug_mode_go(0)
	}

	// 加载配置
	var err error
	debugPrint("Loading configuration from: %s", configPath)
	config, err = loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	debugPrint("Config loaded successfully: %+v", config)

	printStartupInfo()

	// 设置 Gin 为发布模式
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	signMode = strings.ToLower(strings.TrimSpace(config.SignMode))
	if signMode == "" {
		signMode = "dlopen"
	}

	if signMode == "attach" {
		if wrapperPathParam != "" {
			wrapperPath = wrapperPathParam
		} else if config.Env.QQAppDir != "" {
			wrapperPath = filepath.Join(config.Env.QQAppDir, "wrapper.node")
		} else if detected := detectQQAppDir(); detected != "" {
			wrapperPath = filepath.Join(detected, "wrapper.node")
		}
		if err := initAttachMode(config); err != nil {
			log.Fatalf("Failed to initialize attach mode: %v", err)
		}
		wrapperDir := filepath.Dir(wrapperPath)
		if wrapperDir == "." {
			wrapperDir = config.Env.QQAppDir
		}
		runStartupAutoDetect(qqAppDirParam, wrapperDir)
	} else if wrapperPathParam == "" {
		debugPrint("No wrapper-path provided, using default...")
		// 从配置文件或命令行参数获取 wrapper 目录
		wrapperDir := "/app/data" // 默认值
		// 这里可以添加从配置文件读取 wrapper 目录的逻辑
		wrapperPath = filepath.Join(wrapperDir, "wrapper.node")
		debugPrint("Using default wrapper path: %s", wrapperPath)
		
		// 检查文件是否存在
		debugPrint("Checking if wrapper.node file exists...")
		if _, err := os.Stat(wrapperPath); os.IsNotExist(err) {
			log.Printf("ERROR: wrapper.node file does not exist: %s", wrapperPath)
			log.Printf("Current working directory: %s", getCurrentWorkingDirectory())
			log.Fatalf("Please ensure wrapper.node file exists at the default location or provide -wrapper-path argument")
		} else if err != nil {
			log.Printf("ERROR: Failed to stat wrapper.node file: %v", err)
			log.Fatalf("File system error")
		} else {
			debugPrint("SUCCESS: wrapper.node file exists")
		}
		
		if err := setupRuntimeEnvironment(wrapperDir, config, qqAppDirParam); err != nil {
			log.Printf("WARNING: runtime environment setup: %v", err)
		}

		runStartupAutoDetect(qqAppDirParam, wrapperDir)

		debugPrint("Calling initSignModule...")
		if err := initSignModule(config, wrapperDir); err != nil {
			log.Fatalf("Failed to initialize sign module: %v", err)
		}
	} else {
		debugPrint("Wrapper-path provided: %s", wrapperPathParam)
		// 直接使用传入的 wrapper.node 文件路径
		wrapperPath = wrapperPathParam
		debugPrint("Using provided wrapper path: %s", wrapperPath)
		
		// 检查文件是否存在
		debugPrint("Checking if wrapper.node file exists...")
		if _, err := os.Stat(wrapperPath); os.IsNotExist(err) {
			log.Printf("ERROR: wrapper.node file does not exist: %s", wrapperPath)
			log.Printf("Current working directory: %s", getCurrentWorkingDirectory())
			log.Fatalf("Please ensure wrapper.node file path is correct")
		} else if err != nil {
			log.Printf("ERROR: Failed to stat wrapper.node file: %v", err)
			log.Fatalf("File system error")
		} else {
			debugPrint("SUCCESS: wrapper.node file exists")
		}
		
		wrapperDir := filepath.Dir(wrapperPath)
		if err := setupRuntimeEnvironment(wrapperDir, config, qqAppDirParam); err != nil {
			log.Printf("WARNING: runtime environment setup: %v", err)
		}

		runStartupAutoDetect(qqAppDirParam, wrapperDir)

		debugPrint("Calling initSignModuleWithPath...")
		if err := initSignModuleWithPath(config, wrapperPath); err != nil {
			log.Fatalf("Failed to initialize sign module: %v", err)
		}
	}

	// 打印 wrapper.node 路径信息
	fmt.Println("---")
	fmt.Printf("签名模式：%s\n", signMode)
	if signMode == "attach" {
		fmt.Printf("Attach bridge：%s\n", attachBridgeSocket)
		if attachQQPID > 0 {
			fmt.Printf("QQ 进程：pid=%d base=0x%X\n", attachQQPID, attachWrapperBase)
		}
	}
	fmt.Printf("Wrapper.node：%s\n", wrapperPath)
	fmt.Println("╚══════════════════════════════════╝")

	// 注册路由
	debugPrint("Registering routes...")
	registerRoutes(r)

	// 解析监听地址
	debugPrint("Parsing listen address: %s", config.Listen)
	host, port := parseListenAddr(config.Listen)
	if host == "" {
		host = "0.0.0.0"
	}
	if port == "" {
		port = "8080"
	}

	debugPrint("Starting server: http://%s:%s", host, port)
	if err := r.Run(host + ":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// getCurrentWorkingDirectory 获取当前工作目录
func getCurrentWorkingDirectory() string {
	dir, err := os.Getwd()
	if err != nil {
		return "无法获取当前目录"
	}
	return dir
}

// printStartupInfo 打印启动信息和版权信息
func printStartupInfo() {
	fmt.Println("╔══ YanXiYu LinuxNT Sign ══╗")
	fmt.Println("YanXiYu LinuxNT Sign — 公益 NTQQ 签名服务")
	fmt.Println("https://github.com/CatnipHub/LgrNTQQsignserver_v2")
}

// loadConfig 加载配置文件
func loadConfig(path string) (*Config, error) {
	debugPrint("Loading config from: %s", path)
	
	// 检查文件是否存在
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("ERROR: Config file does not exist: %s", path)
		return nil, fmt.Errorf("配置文件不存在: %s", path)
	}
	
	var config Config
	if _, err := toml.DecodeFile(path, &config); err != nil {
		log.Printf("ERROR: Failed to decode config file: %v", err)
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}
	
	// 设置默认值
	if config.AdminKey == "" {
		config.AdminKey = "default_admin_key"
	}
	if config.TokenTimeout == 0 {
		config.TokenTimeout = 3600 // 1小时
	}
	if config.Env.Display == "" {
		config.Env.Display = ":99"
	}
	rawConfig, _ := os.ReadFile(path)
	// 未写 auto_setup 时默认开启；仅当配置里显式出现该字段时尊重用户值
	if len(rawConfig) == 0 || !bytes.Contains(rawConfig, []byte("auto_setup")) {
		config.Env.AutoSetup = true
	}
	if config.Env.AutoSetup && !config.Env.CopyFromQQ && config.Env.QQAppDir != "" {
		config.Env.CopyFromQQ = true
	}
	if len(rawConfig) == 0 || !bytes.Contains(rawConfig, []byte("chdir_to_wrapper")) {
		config.Env.ChdirToWrapper = true
	}
	if config.Env.Timezone == "" {
		config.Env.Timezone = "Asia/Shanghai"
	}
	if len(rawConfig) == 0 || !bytes.Contains(rawConfig, []byte("offset_auto")) {
		if config.Offset == "" {
			config.OffsetAuto = true
		}
	}

	debugPrint("Config loaded successfully: %+v", config)
	debugPrint("Preloads array length: %d, contents: %v", len(config.Preloads), config.Preloads)
	return &config, nil
}

// debugPrint 条件调试打印函数
func debugPrint(format string, v ...interface{}) {
	if debugMode {
		log.Printf(format, v...)
	}
}

// initSignModule 初始化签名模块（使用目录路径）
func initSignModule(config *Config, wrapperDir string) error {
	debugPrint("DEBUG: initSignModule called with wrapperDir: %s", wrapperDir)
	debugPrint("DEBUG: config: %+v", config)
	
	// 检查目录是否存在
	if _, err := os.Stat(wrapperDir); os.IsNotExist(err) {
		log.Printf("ERROR: wrapper directory does not exist: %s", wrapperDir)
		return fmt.Errorf("wrapper目录不存在: %s", wrapperDir)
	}
	
	// 设置 wrapper 目录
	cWrapperDir := C.CString(wrapperDir)
	defer C.free(unsafe.Pointer(cWrapperDir))
	debugPrint("DEBUG: Calling C.set_wrapper_path_go")
	C.set_wrapper_path_go(cWrapperDir)

	applyResolvedPreloads(config, wrapperDir, detectQQAppDirFromConfig(config))

	offset, err := resolveSignOffset(config, filepath.Join(wrapperDir, "wrapper.node"))
	if err != nil {
		return err
	}
	debugPrint("DEBUG: Setting offset: 0x%x", offset)
	C.set_offset_go(C.ulonglong(offset))

	// 加载模块
	debugPrint("DEBUG: Calling C.load_module_go...")
	result := C.load_module_go()
	debugPrint("DEBUG: C.load_module_go returned: %d", int(result))
	if result != 0 {
		log.Printf("ERROR: Failed to load module, C function returned: %d", int(result))
		return fmt.Errorf("加载签名模块失败，返回码: %d", int(result))
	}

	debugPrint("DEBUG: Sign module initialized successfully")
	return nil
}

// initSignModuleWithPath 初始化签名模块（使用文件路径）
func initSignModuleWithPath(config *Config, wrapperPath string) error {
	debugPrint("DEBUG: initSignModuleWithPath called with wrapperPath: %s", wrapperPath)
	debugPrint("DEBUG: config: %+v", config)
	
	// 检查文件是否存在
	fileInfo, err := os.Stat(wrapperPath)
	if os.IsNotExist(err) {
		log.Printf("ERROR: wrapper.node file does not exist: %s", wrapperPath)
		return fmt.Errorf("wrapper.node文件不存在: %s", wrapperPath)
	}
	if err != nil {
		log.Printf("ERROR: Failed to stat wrapper.node file: %v", err)
		return fmt.Errorf("检查wrapper.node文件时出错: %v", err)
	}
	
	// 检查文件权限
	if fileInfo.Mode()&0111 == 0 {
		log.Printf("WARNING: wrapper.node file may not have execute permissions: %s", wrapperPath)
	}
	
	debugPrint("DEBUG: wrapper.node file size: %d bytes", fileInfo.Size())
	
	// 获取 wrapper.node 文件所在的目录
	wrapperDir := filepath.Dir(wrapperPath)
	debugPrint("DEBUG: Wrapper directory: %s", wrapperDir)
	
	// 检查目录是否存在
	if _, err := os.Stat(wrapperDir); os.IsNotExist(err) {
		log.Printf("ERROR: wrapper directory does not exist: %s", wrapperDir)
		return fmt.Errorf("wrapper目录不存在: %s", wrapperDir)
	}
	
	// 设置 wrapper 目录
	cWrapperDir := C.CString(wrapperDir)
	defer C.free(unsafe.Pointer(cWrapperDir))
	debugPrint("DEBUG: Calling C.set_wrapper_path_go")
	C.set_wrapper_path_go(cWrapperDir)

	applyResolvedPreloads(config, wrapperDir, detectQQAppDirFromConfig(config))

	offset, err := resolveSignOffset(config, wrapperPath)
	if err != nil {
		return err
	}
	debugPrint("DEBUG: Setting offset: 0x%x", offset)
	C.set_offset_go(C.ulonglong(offset))

	// 加载模块
	debugPrint("DEBUG: Calling C.load_module_go...")
	result := C.load_module_go()
	debugPrint("DEBUG: C.load_module_go returned: %d", int(result))
	if result != 0 {
		log.Printf("ERROR: Failed to load module, C function returned: %d", int(result))
		// 提供更具体的错误信息和解决建议
		errorMsg := "加载签名模块失败"
		if int(result) == 1 {
			errorMsg += "，可能是缺少系统依赖库，请尝试在配置文件中添加: preloads = [\"/usr/lib/x86_64-linux-gnu/libgnutls.so.30\"]"
		}
		return fmt.Errorf("%s，返回码: %d", errorMsg, int(result))
	}

	debugPrint("DEBUG: Sign module initialized successfully with wrapper.node file: %s", wrapperPath)
	return nil
}

// registerRoutes 注册 HTTP 路由
func registerRoutes(r *gin.Engine) {
	r.GET("/", handleHomeRequest)
	r.POST("/sign", handleSignRequest)
	r.GET("/sign", handleSignRequest)
	r.GET("/appinfo_v2", handleAppInfoRequest)
	r.GET("/sign/appinfo_v2", handleAppInfoRequest)
	r.GET("/attach/status", handleAttachStatus)
	r.GET("/env/status", handleEnvStatus)
}

func handleHomeRequest(c *gin.Context) {
	visitStats.HomePage.Add(1)
	c.JSON(http.StatusOK, YanXiYuHomeResponse{
		Status:      "ok",
		Title:       "YanXiYu LinuxNT Sign",
		Description: "欢迎来到YanXiYu LinuxNT Sign首页喵~ 本签名为公益签名哦~",
		Version:     "Release_1.0.0 Golang",
		Pages: map[string]string{
			"HomePage": "/",
			"appinfo":  "/appinfo_v2",
			"sign":     "/sign",
		},
		Static:    snapshotPageStats(),
		QQVersion: currentQQVersion(),
	})
}

// handleSignRequest 处理签名请求的 HTTP 处理函数
func handleSignRequest(c *gin.Context) {
	// 检查请求方法，GET 请求通常不包含请求体
	if c.Request.Method == "GET" {
		// 对于 GET 请求，可以从查询参数中获取数据
		cmd := c.Query("cmd")
		src := c.Query("src")
		seqStr := c.Query("seq")
		
		// 如果是 GET 请求且没有查询参数，则返回错误信息
		if cmd == "" && src == "" && seqStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "GET 请求需要提供 cmd, src, seq 查询参数，或使用 POST 方法发送 JSON 数据"})
			return
		}
		
		// 解析序列号
		seq := 0
		if seqStr != "" {
			if parsedSeq, err := strconv.Atoi(seqStr); err == nil {
				seq = parsedSeq
			}
		}
		
		visitStats.Sign.Add(1)
		result, err := sign(cmd, src, seq)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, result)
		return
	}

	// 解析请求体中的 JSON 数据
	var req SignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 JSON 数据: " + err.Error()})
		return
	}

	visitStats.Sign.Add(1)
	result, err := sign(req.Cmd, req.Src, req.Seq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func handleAppInfoRequest(c *gin.Context) {
	visitStats.Appinfo.Add(1)
	appInfo, err := getAppInfo()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 返回 AppInfo 数据
	c.Data(http.StatusOK, "application/json", appInfo)
}

// sign 执行实际的签名操作
func sign(cmd, srcHex string, seq int) (*Response, error) {
	if signMode == "attach" {
		return signViaAttachBridge(cmd, srcHex, seq)
	}

	// 解码十六进制字符串为字节数组
	srcBytes, err := hex.DecodeString(strings.ToUpper(srcHex))
	if err != nil {
		return nil, fmt.Errorf("src 参数必须是有效的十六进制字符串")
	}

	// 准备传递给 C 函数的参数
	cCmd := C.CString(cmd)                     // 命令字符串
	defer C.free(unsafe.Pointer(cCmd))         // 函数退出时释放内存
	cSrc := (*C.uchar)(&srcBytes[0])           // 源数据指针
	cSrcLen := C.int(len(srcBytes))            // 源数据长度
	cSeq := C.int(seq)                         // 序列号

	// 准备输出缓冲区 (0x300 字节)
	outputBuffer := make([]byte, 0x300)
	cOutput := (*C.uchar)(&outputBuffer[0])    // 输出缓冲区指针

	// 调用 C 函数执行签名操作
	result := C.sign_go(cCmd, cSrc, cSrcLen, cSeq, cOutput)
	if result != 0 {
		return nil, fmt.Errorf("签名失败，错误码: %d", int(result))
	}

	// 解析输出缓冲区中的结果
	tokenLen := int(outputBuffer[0x0FF])                            // Token 长度
	tokenEnd := 0x000 + tokenLen
	if tokenEnd > len(outputBuffer) {
		tokenEnd = len(outputBuffer)
	}
	token := hex.EncodeToString(outputBuffer[0x000:tokenEnd]) // Token 数据

	extraLen := int(outputBuffer[0x1FF])                            // Extra 长度
	extraStart := 0x100
	extraEnd := extraStart + extraLen
	if extraEnd > len(outputBuffer) {
		extraEnd = len(outputBuffer)
	}
	extra := hex.EncodeToString(outputBuffer[extraStart:extraEnd]) // Extra 数据

	signLen := int(outputBuffer[0x2FF])                             // Sign 长度
	signStart := 0x200
	signEnd := signStart + signLen
	if signEnd > len(outputBuffer) {
		signEnd = len(outputBuffer)
	}
	sign := hex.EncodeToString(outputBuffer[signStart:signEnd])   // Sign 数据

	// 构造响应结果
	response := &Response{
		Value: ResponseValue{
			Token: strings.ToUpper(token),  // 转换为大写
			Extra: strings.ToUpper(extra),  // 转换为大写
			Sign:  strings.ToUpper(sign),   // 转换为大写
		},
	}

	return response, nil
}

func getAppInfo() ([]byte, error) {
	if cachedAppInfo.CurrentVersion != "" || cachedAppInfo.SubAppId > 0 {
		return json.Marshal(cachedAppInfo)
	}

	appinfoPath := filepath.Join(filepath.Dir(wrapperPath), "appinfo.json")
	if _, err := os.Stat(appinfoPath); err == nil {
		// 读取 appinfo.json 文件
		data, err := os.ReadFile(appinfoPath)
		if err == nil {
			// 验证是否为有效的 JSON
			var result interface{}
			if json.Unmarshal(data, &result) == nil {
				// 检查是否为旧版格式，如果是则自动转换
				if isNewFormat, convertedData := convertIfOldFormat(data); isNewFormat {
					// 如果是旧版格式，保存转换后的新版格式
					go saveConvertedAppInfo(appinfoPath, convertedData)
					return convertedData, nil
				}
				return data, nil
			}
		}
	}

	// 检查是否存在对应版本的文件
	versionFile := config.Version + ".json"
	if _, err := os.Stat(versionFile); err == nil {
		// 读取现有文件并转换为新格式
		data, err := os.ReadFile(versionFile)
		if err == nil {
			// 检查是否为旧版格式，如果是则自动转换
			if isNewFormat, convertedData := convertIfOldFormat(data); isNewFormat {
				// 如果是旧版格式，保存转换后的新版格式
				go saveConvertedAppInfo(versionFile, convertedData)
				return convertedData, nil
			}
			return convertToNewFormat(data, config.Version)
		}
	}

	return json.Marshal(buildDefaultAppInfo(config.Version))
}

// convertIfOldFormat 检查并转换旧版格式为新版格式
func convertIfOldFormat(data []byte) (bool, []byte) {
	// 定义旧版格式的关键字段
	oldFormatFields := []string{"MiscBitmap", "AppClientVersion", "MainSigMap", "SubSigMap"}
	
	// 解析 JSON
	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return false, nil
	}
	
	// 检查是否存在旧版格式的字段
	for _, field := range oldFormatFields {
		if _, exists := jsonData[field]; exists {
			// 存在旧版字段，检查是否缺少新版字段
			if _, exists := jsonData["SdkInfo"]; !exists {
				// 确实是旧版格式，进行转换
				converted, err := convertToNewFormat(data, "")
				if err != nil {
					return false, nil
				}
				return true, converted
			}
		}
	}
	
	// 检查是否已经是新版格式
	if _, exists := jsonData["SdkInfo"]; exists {
		// 已经是新版格式
		return false, data
	}
	
	return false, data
}

// saveConvertedAppInfo 保存转换后的 AppInfo 到文件
func saveConvertedAppInfo(filePath string, data []byte) {
	// 创建备份文件
	backupPath := filePath + ".bak"
	if err := copyFile(filePath, backupPath); err != nil {
		log.Printf("Warning: Failed to create backup of %s: %v", filePath, err)
	}
	
	// 保存转换后的文件
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		log.Printf("Warning: Failed to save converted AppInfo to %s: %v", filePath, err)
	} else {
		log.Printf("Successfully converted and saved AppInfo to %s", filePath)
	}
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// convertToNewFormat 将旧格式的 AppInfo 转换为新格式
func convertToNewFormat(oldData []byte, version string) ([]byte, error) {
	// 定义旧格式结构体
	type OldAppInfo struct {
		Os              string `json:"Os"`
		VendorOs        string `json:"VendorOs"`
		Kernel          string `json:"Kernel"`
		CurrentVersion  string `json:"CurrentVersion"`
		MiscBitmap      int    `json:"MiscBitmap"`
		PtVersion       string `json:"PtVersion"`
		SsoVersion      int    `json:"SsoVersion"`
		PackageName     string `json:"PackageName"`
		WtLoginSdk      string `json:"WtLoginSdk"`
		AppId           int64  `json:"AppId"`
		SubAppId        int64  `json:"SubAppId"`
		AppIdQrCode     int64  `json:"AppIdQrCode"`
		AppClientVersion int   `json:"AppClientVersion"`
		MainSigMap      int    `json:"MainSigMap"`
		SubSigMap       int    `json:"SubSigMap"`
		NTLoginType     int    `json:"NTLoginType"`
	}

	var oldAppInfo OldAppInfo
	if err := json.Unmarshal(oldData, &oldAppInfo); err != nil {
		return nil, err
	}

	// 转换为新格式
	newAppInfo := AppInfoResponse{
		Os:               oldAppInfo.Os,
		VendorOs:         oldAppInfo.VendorOs,
		Kernel:           oldAppInfo.Kernel,
		Qua:              "0",
		CurrentVersion:   oldAppInfo.CurrentVersion,
		PtVersion:        oldAppInfo.PtVersion,
		SsoVersion:       oldAppInfo.SsoVersion,
		PackageName:      oldAppInfo.PackageName,
		WtLoginSdk:       oldAppInfo.WtLoginSdk,
		SdkInfo: SdkInfo{
			SdkBuildTime: 0,
			SdkVersion:   "0",
			MiscBitMap:   oldAppInfo.MiscBitmap,
			SubSigMap:    oldAppInfo.SubSigMap,
			MainSigMap:   oldAppInfo.MainSigMap,
		},
		AppId:            oldAppInfo.AppId,
		AppIdQrCode:      oldAppInfo.AppIdQrCode,
		SubAppId:         oldAppInfo.SubAppId,
		AppClientVersion: oldAppInfo.AppClientVersion,
		NTLoginType:      oldAppInfo.NTLoginType,
	}

	return json.Marshal(newAppInfo)
}

// parseListenAddr 解析监听地址，分离主机和端口
func parseListenAddr(listen string) (host, port string) {
	parts := strings.Split(listen, ":")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

// setupRuntimeEnvironment 在 dlopen 加载 wrapper.node 前补齐运行目录、配置和环境变量
func setupRuntimeEnvironment(wrapperDir string, cfg *Config, qqAppDirOverride string) error {
	report := map[string]interface{}{
		"enabled":    cfg.Env.AutoSetup,
		"sign_mode":  signMode,
		"wrapperDir": wrapperDir,
	}
	defer func() { runtimeEnvReport = report }()

	if !cfg.Env.AutoSetup {
		debugPrint("Runtime environment auto setup disabled")
		return nil
	}

	qqAppDir := resolveQQAppDir(cfg, qqAppDirOverride)
	dataPath := resolveDataPath(wrapperDir, cfg.Env.DataPath)
	report["qqAppDir"] = qqAppDir
	report["dataPath"] = dataPath

	debugPrint("Setting up runtime environment: wrapperDir=%s qqAppDir=%s dataPath=%s", wrapperDir, qqAppDir, dataPath)

	copied := []string{}
	if cfg.Env.CopyFromQQ && qqAppDir != "" {
		items, err := copyQQRuntimeFiles(qqAppDir, wrapperDir, cfg.Env.SyncFromQQ)
		copied = items
		if err != nil {
			debugPrint("Copy from QQ app dir failed: %v", err)
			report["copy_error"] = err.Error()
		}
	}
	report["copied"] = copied

	checks := map[string]bool{}
	for _, step := range []struct {
		name string
		fn   func() error
	}{
		{"directories", func() error { return ensureRuntimeDirectories(wrapperDir, dataPath) }},
		{"resources_app_symlink", func() error { return ensureResourcesAppSymlink(wrapperDir) }},
		{"config.env.json", func() error { return ensureConfigEnvJSON(wrapperDir, qqAppDir, cfg.Env.SyncFromQQ) }},
		{"package.json", func() error { return ensurePackageJSON(wrapperDir, cfg.Version, qqAppDir, cfg.Env.SyncFromQQ) }},
		{"appinfo.json", func() error { return ensureAppInfoFile(wrapperDir, cfg.Version, qqAppDir, cfg.Env.SyncFromQQ) }},
		{"versions_config", func() error { return ensureVersionsConfig(wrapperDir, cfg.Version, qqAppDir, cfg.Env.SyncFromQQ) }},
	} {
		err := step.fn()
		checks[step.name] = err == nil
		if err != nil {
			report[step.name+"_error"] = err.Error()
		}
	}
	report["checks"] = checks

	preloads := resolvePreloads(wrapperDir, qqAppDir, cfg)
	report["preloads"] = preloads
	applyProcessEnvironment(wrapperDir, dataPath, cfg.Env)

	if cfg.Env.ChdirToWrapper && signMode == "dlopen" {
		if err := os.Chdir(wrapperDir); err != nil {
			return fmt.Errorf("切换到 wrapper 目录失败: %w", err)
		}
		cwd, _ := os.Getwd()
		report["cwd"] = cwd
		log.Printf("Changed working directory to wrapper dir: %s", cwd)
	}

	log.Printf("Runtime environment prepared (wrapper=%s, data=%s, qqApp=%s)", wrapperDir, dataPath, qqAppDir)
	return nil
}

func resolveQQAppDir(cfg *Config, override string) string {
	if override != "" {
		return override
	}
	if cfg.Env.QQAppDir != "" {
		return cfg.Env.QQAppDir
	}
	return detectQQAppDir()
}

func detectQQAppDirFromConfig(cfg *Config) string {
	return resolveQQAppDir(cfg, "")
}

func resolveDataPath(wrapperDir, configured string) string {
	if configured != "" {
		return configured
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(wrapperDir, ".qq-data")
	}
	return filepath.Join(home, ".config", "QQ")
}

func detectQQAppDir() string {
	candidates := []string{
		"/opt/QQ/resources/app",
		"/opt/QQNT/resources/app",
		"/usr/lib/qq/resources/app",
	}
	for _, dir := range candidates {
		if fileExists(filepath.Join(dir, "wrapper.node")) || fileExists(filepath.Join(dir, "package.json")) {
			return dir
		}
	}
	return ""
}

func ensureRuntimeDirectories(wrapperDir, dataPath string) error {
	dirs := []string{
		filepath.Join(wrapperDir, "nt_temp"),
		filepath.Join(wrapperDir, "sharp-lib"),
		filepath.Join(wrapperDir, "versions"),
		filepath.Join(wrapperDir, "resources"),
		filepath.Join(dataPath, "crash_files"),
		filepath.Join(dataPath, "versions"),
		filepath.Join(dataPath, "nt_temp"),
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".config", "tencent-qq"))
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败 %s: %w", dir, err)
		}
		debugPrint("Ensured directory: %s", dir)
	}
	transInfo := filepath.Join(dataPath, "crash_files", ".trans_info")
	if !fileExists(transInfo) {
		if err := os.WriteFile(transInfo, []byte("{}"), 0644); err != nil {
			return fmt.Errorf("创建 .trans_info 失败: %w", err)
		}
		debugPrint("Created %s", transInfo)
	}
	return nil
}

func handleEnvStatus(c *gin.Context) {
	if runtimeEnvReport == nil {
		c.JSON(http.StatusOK, gin.H{
			"sign_mode": signMode,
			"message":   "环境尚未初始化或 auto_setup 已关闭",
		})
		return
	}
	c.JSON(http.StatusOK, runtimeEnvReport)
}

func applyResolvedPreloads(cfg *Config, wrapperDir, qqAppDir string) {
	for _, p := range preloadLibCSStrings {
		C.free(unsafe.Pointer(p))
	}
	preloadLibCSStrings = nil
	preloadLibCArray = nil

	preloads := resolvePreloads(wrapperDir, qqAppDir, cfg)
	if len(preloads) == 0 {
		debugPrint("DEBUG: No libraries to preload")
		C.set_libs_go(nil)
		return
	}
	debugPrint("DEBUG: Preloading libraries: %v", preloads)
	for _, lib := range preloads {
		cs := C.CString(lib)
		preloadLibCSStrings = append(preloadLibCSStrings, cs)
		preloadLibCArray = append(preloadLibCArray, cs)
	}
	preloadLibCArray = append(preloadLibCArray, nil)
	C.set_libs_go(&preloadLibCArray[0])
}

func resolvePreloads(wrapperDir, qqAppDir string, cfg *Config) []string {
	candidates := append([]string{}, cfg.Preloads...)
	candidates = append(candidates,
		filepath.Join(wrapperDir, "libbugly.so"),
		filepath.Join(wrapperDir, "libcrbase.so"),
		filepath.Join(qqAppDir, "libbugly.so"),
		filepath.Join(qqAppDir, "libcrbase.so"),
		filepath.Join(wrapperDir, "sharp-lib", "libbugly.so"),
		"/usr/lib/x86_64-linux-gnu/libX11-xcb.so.1",
		"/usr/lib/x86_64-linux-gnu/libX11.so.6",
		"/usr/lib/x86_64-linux-gnu/libXext.so.6",
		"/usr/lib/x86_64-linux-gnu/libvips-cpp.so.42",
		"/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
		"/lib/x86_64-linux-gnu/libgnutls.so.30",
		"libX11-xcb.so.1",
		"libX11.so.6",
		"libXext.so.6",
		"libgnutls.so.30",
	)
	if sharpDir := filepath.Join(wrapperDir, "sharp-lib"); fileExists(sharpDir) {
		_ = filepath.Walk(sharpDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".so") || strings.Contains(filepath.Base(path), ".so.") {
				candidates = append(candidates, path)
			}
			return nil
		})
	}
	unique := make([]string, 0, len(candidates))
	seen := map[string]struct{}{}
	for _, item := range candidates {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !fileExists(item) {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		unique = append(unique, item)
	}
	return unique
}

func ensureResourcesAppSymlink(wrapperDir string) error {
	resourcesDir := filepath.Join(wrapperDir, "resources")
	appLink := filepath.Join(resourcesDir, "app")
	if fileExists(appLink) {
		return nil
	}
	if err := os.MkdirAll(resourcesDir, 0755); err != nil {
		return err
	}
	if err := os.Symlink(wrapperDir, appLink); err != nil {
		return err
	}
	debugPrint("Created resources/app symlink -> %s", wrapperDir)
	return nil
}

func ensureVersionsConfig(wrapperDir, version, qqAppDir string, sync bool) error {
	targetDir := filepath.Join(wrapperDir, "versions")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}
	target := filepath.Join(targetDir, "config.json")
	src := ""
	if qqAppDir != "" {
		src = filepath.Join(qqAppDir, "versions", "config.json")
		if !fileExists(src) {
			src = filepath.Join(filepath.Dir(filepath.Dir(qqAppDir)), "versions", "config.json")
		}
	}
	if fileExists(src) {
		return copyFileWithPolicy(src, target, sync)
	}
	if fileExists(target) {
		return nil
	}
	payload := map[string]interface{}{
		"curVersion": version,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(target, data, 0644)
}

func ensureConfigEnvJSON(wrapperDir, qqAppDir string, sync bool) error {
	target := filepath.Join(wrapperDir, "config.env.json")
	src := filepath.Join(qqAppDir, "config.env.json")
	if qqAppDir != "" && fileExists(src) {
		if err := copyFileWithPolicy(src, target, sync); err != nil {
			return err
		}
		return nil
	}
	if fileExists(target) {
		debugPrint("config.env.json already exists: %s", target)
		return nil
	}
	payload := ConfigEnvJSON{
		EnableEnvConfig:     false,
		DefaultSamplingRate: 100,
		IsTestEnv:           false,
		IP:                  "",
		Port:                0,
		EnvID:               "prod",
		Canary:              "",
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(target, data, 0644); err != nil {
		return err
	}
	log.Printf("Generated default config.env.json at %s", target)
	return nil
}

func ensurePackageJSON(wrapperDir, version, qqAppDir string, sync bool) error {
	target := filepath.Join(wrapperDir, "package.json")
	src := filepath.Join(qqAppDir, "package.json")
	if qqAppDir != "" && fileExists(src) {
		if err := copyFileWithPolicy(src, target, sync); err != nil {
			return err
		}
		return nil
	}
	if fileExists(target) {
		return nil
	}
	if version == "" {
		version = "3.2.22-42941"
	}
	payload := PackageJSON{
		Name:    "qq-resources-app",
		Version: version,
		Qua:     buildLinuxQua(version),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(target, data, 0644); err != nil {
		return err
	}
	log.Printf("Generated default package.json at %s", target)
	return nil
}

func buildLinuxQua(version string) string {
	return "V1_LINUX_NQ_" + strings.ReplaceAll(version, "-", "_") + "_GW_B"
}

func parseAppClientVersion(version string) int {
	parts := strings.Split(version, "-")
	if len(parts) < 2 {
		return 0
	}
	n, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return 0
	}
	return n
}

func buildDefaultAppInfo(version string) AppInfoResponse {
	if version == "" {
		version = "3.2.22-42941"
	}
	clientVer := parseAppClientVersion(version)
	if clientVer == 0 {
		clientVer = 42941
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
		WtLoginSdk:     "nt.wtlogin.0.0.1",
		SdkInfo: SdkInfo{
			SdkBuildTime: 0,
			SdkVersion:   "0",
			MiscBitMap:   32764,
			SubSigMap:    0,
			MainSigMap:   169742560,
		},
		AppId:            1600001615,
		AppIdQrCode:      537328659,
		SubAppId:         537328659,
		AppClientVersion: clientVer,
		NTLoginType:      1,
	}
}

func ensureAppInfoFile(wrapperDir, version, qqAppDir string, sync bool) error {
	target := filepath.Join(wrapperDir, "appinfo.json")
	src := filepath.Join(qqAppDir, "appinfo.json")
	if qqAppDir != "" && fileExists(src) {
		if err := copyFileWithPolicy(src, target, sync); err != nil {
			return err
		}
		return nil
	}
	if fileExists(target) {
		return nil
	}
	data, err := json.MarshalIndent(buildDefaultAppInfo(version), "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(target, data, 0644); err != nil {
		return err
	}
	log.Printf("Generated default appinfo.json at %s", target)
	return nil
}

func applyProcessEnvironment(wrapperDir, dataPath string, env EnvSettings) {
	display := env.Display
	if display == "" {
		display = ":99"
	}
	setEnvIfEmpty("DISPLAY", display)
	setEnvIfEmpty("XDG_SESSION_TYPE", "x11")
	setEnvIfEmpty("TZ", env.Timezone)
	setEnvIfEmpty("LANG", "en_US.UTF-8")
	setEnvIfEmpty("LC_ALL", "en_US.UTF-8")

	pathEntries := []string{
		wrapperDir,
		filepath.Join(wrapperDir, "sharp-lib"),
		filepath.Join(wrapperDir, "resources", "app"),
	}
	if cur := os.Getenv("LD_LIBRARY_PATH"); cur != "" {
		pathEntries = append(pathEntries, strings.Split(cur, ":")...)
	}
	unique := make([]string, 0, len(pathEntries))
	seen := map[string]struct{}{}
	for _, p := range pathEntries {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		unique = append(unique, p)
	}
	_ = os.Setenv("LD_LIBRARY_PATH", strings.Join(unique, ":"))
	_ = os.Setenv("QQNT_DATA_PATH", dataPath)
	_ = os.Setenv("QQNT_BASE_PATH", wrapperDir)
	_ = os.Setenv("QQ_PACKAGE_ROOT", wrapperDir)
	_ = os.Setenv("RESOURCES_PATH", filepath.Join(wrapperDir, "resources", "app"))
	debugPrint("Environment: DISPLAY=%s TZ=%s LD_LIBRARY_PATH=%s QQNT_DATA_PATH=%s QQNT_BASE_PATH=%s",
		os.Getenv("DISPLAY"), os.Getenv("TZ"), os.Getenv("LD_LIBRARY_PATH"), dataPath, wrapperDir)
}

func setEnvIfEmpty(key, value string) {
	if os.Getenv(key) == "" {
		_ = os.Setenv(key, value)
	}
}

func copyQQRuntimeFiles(qqAppDir, wrapperDir string, sync bool) ([]string, error) {
	if !fileExists(qqAppDir) {
		return nil, fmt.Errorf("qq app dir not found: %s", qqAppDir)
	}
	log.Printf("Copying runtime files from QQ app dir: %s (sync=%v)", qqAppDir, sync)
	copied := []string{}
	files := []string{"config.env.json", "package.json", "appinfo.json", "libbugly.so", "libcrbase.so"}
	for _, name := range files {
		src := filepath.Join(qqAppDir, name)
		dst := filepath.Join(wrapperDir, name)
		if !fileExists(src) {
			continue
		}
		if err := copyFileWithPolicy(src, dst, sync); err != nil {
			return copied, err
		}
		copied = append(copied, name)
	}
	sharpSrc := filepath.Join(qqAppDir, "sharp-lib")
	sharpDst := filepath.Join(wrapperDir, "sharp-lib")
	if fileExists(sharpSrc) {
		if err := copyDirWithPolicy(sharpSrc, sharpDst, sync); err != nil {
			return copied, err
		}
		copied = append(copied, "sharp-lib/")
	}
	versionsSrc := filepath.Join(qqAppDir, "versions")
	versionsDst := filepath.Join(wrapperDir, "versions")
	if fileExists(versionsSrc) {
		if err := copyDirWithPolicy(versionsSrc, versionsDst, sync); err != nil {
			return copied, err
		}
		copied = append(copied, "versions/")
	}
	return copied, nil
}

func copyFileWithPolicy(src, dst string, sync bool) error {
	if !sync && fileExists(dst) {
		debugPrint("Skip existing file: %s", dst)
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return err
	}
	log.Printf("Copied %s -> %s", src, dst)
	return nil
}

func copyDirWithPolicy(src, dst string, sync bool) error {
	if !sync {
		if entries, err := os.ReadDir(dst); err == nil && len(entries) > 0 {
			debugPrint("Skip existing directory: %s", dst)
			return nil
		}
	}
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		if !sync && fileExists(target) {
			return nil
		}
		return copyRegularFile(path, target, info.Mode())
	})
}

func copyRegularFile(src, dst string, mode os.FileMode) error {
	if fileExists(dst) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
