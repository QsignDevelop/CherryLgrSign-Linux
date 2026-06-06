# Linux QQ 签名服务器 (Go 版本)

**重要**: 此项目专为 Linux 系统设计，因为它使用了 Linux 特定的库进行动态加载。

## 概述

这是一个使用 Go 语言实现的 NTQQ 签名服务器，提供 HTTP API 用于 QQ 协议签名。它与 QQ 客户端的原生库集成，执行实际的签名操作。

## 主要特性

- **基于 Token 的认证**: 通过 Token 管理确保 API 访问安全
- **管理员 API**: 使用管理员密钥添加和删除 Token
- **统一的 API 端点**: 简化了端点结构
- **新版 AppInfo 格式**: 更新了 AppInfo 响应格式
- **灵活启动**: 支持直接指定 wrapper.node 文件路径
- **自定义 AppInfo**: 支持在 wrapper 目录中使用自定义的 appinfo.json
- **自动 AppInfo 转换**: 自动将旧版 AppInfo 格式转换为新版格式
- **调试模式**: 使用 --debug 参数可查看详细日志

## 运行环境

- Linux 系统 (推荐 Ubuntu 20.04)
- Go 1.21 或更高版本
- QQ 客户端文件 (特别是 `wrapper.node`)

## 快速开始

### 1. 下载 Linux 版 QQ
从官方网站或包管理器下载 Linux x64 版本的 QQ。

### 2. 解压或安装 QQ
解压下载的 QQ 包或使用包管理器安装：
```bash
# 解压 tar.gz 文件示例
tar -xzf QQ.tar.gz

# 或使用包管理器安装
sudo apt install qq-linux
```

### 3. 定位 wrapper.node 文件
在 QQ 安装目录中找到 `wrapper.node` 文件。通常位于：
```
/path/to/qq/resources/app/wrapper.node
```

### 4. 配置服务器
在项目目录中创建或编辑 `sign.config.toml`：
```toml
# 需要预加载的库文件列表（通常为空，除非需要特定依赖）
preloads = []

# 服务器监听地址和端口
listen = "0.0.0.0:8080"

# 签名函数的内存偏移量（针对特定 QQ 版本）
offset = "0x5ADE220"

# QQ 客户端版本标识符
version = "3.2.19-39038"

# 管理员密钥，用于 Token 管理（请更改为安全值）
admin_key = "your_secret_admin_key_here"

# Token 过期时间（秒）（1 小时 = 3600 秒）
token_timeout = 3600
```

### 5. 运行服务器
选择以下方法之一运行服务器：

#### 方法 1: 直接执行并指定 wrapper.node 路径
```bash
# 直接运行并指定 wrapper.node 文件路径
./sign-server -wrapper-path /path/to/qq/resources/app/wrapper.node

# 使用自定义配置文件运行
./sign-server -wrapper-path /path/to/qq/resources/app/wrapper.node -config /path/to/custom/config.toml

# 使用调试模式运行以查看详细日志
./sign-server -wrapper-path /path/to/qq/resources/app/wrapper.node --debug
```

#### 方法 2: 使用环境变量
```bash
# 设置 wrapper 路径为环境变量
export WRAPPER_PATH=/path/to/qq/resources/app/wrapper.node
./sign-server
```

## 构建二进制文件

### 从源码构建
```bash
# 构建服务器二进制文件
go build -o sign-server main.go

# 使用优化参数构建生产版本
go build -ldflags="-s -w" -o sign-server main.go
```

### 交叉编译（如果在非 Linux 系统上构建）
```bash
# 构建 Linux AMD64 版本
GOOS=linux GOARCH=amd64 go build -o sign-server main.go

# 构建 Linux ARM64 版本
GOOS=linux GOARCH=arm64 go build -o sign-server main.go
```

## API 使用说明

### 首页信息
返回服务器信息和可用端点。
```http
GET /
```
响应:
```json
{
  "status": "ok",
  "title": "NekoGelSign Home",
  "description": "欢迎来到NekoGelSign首页喵~",
  "version": "1.0.0",
  "links": {
    "sign": "/sign",
    "add_tocken": "/add_token",
    "delete_tocken": "/delete_token",
    "appinfo": "/appinfo_v2"
  },
  "message": "喵呜~ 祝你今天也软软糯糯的！(=^･ω･^=)",
  "theme": {
    "color": "#FFC6E5",
    "accent": "#FF92C2",
    "emoji": "🐾✨"
  }
}
```

### Token 管理 API

#### 添加 Token (仅限管理员)
生成新的 API Token 用于认证。
```http
POST /add_token
Content-Type: application/json

{
  "admin_key": "your_secret_admin_key_here"
}
```
响应:
```json
{
  "token": "generated_api_token_string",
  "message": "Token 添加成功"
}
```

#### 删除 Token (仅限管理员)
删除现有的 API Token。
```http
POST /delete_token
Content-Type: application/json

{
  "admin_key": "your_secret_admin_key_here",
  "token": "token_to_delete"
}
```
响应:
```json
{
  "success": true,
  "message": "Token 删除成功"
}
```

### 签名 API

#### 使用 Token 认证 (推荐)
```http
POST /sign
Content-Type: application/json
X-API-Key: your-generated-api-token

{
  "cmd": "MessageSvc.PbSendMsg",
  "seq": 12345,
  "src": "0801120348656C6C6F"
}
```
响应:
```json
{
  "value": {
    "token": "SIGNATURE_TOKEN",
    "extra": "EXTRA_DATA",
    "sign": "ACTUAL_SIGNATURE"
  }
}
```

#### 使用 GET 请求
```http
GET /sign?cmd=MessageSvc.PbSendMsg&seq=12345&src=0801120348656C6C6F
X-API-Key: your-generated-api-token
```

### App Info API
以新格式返回 QQ 客户端应用程序信息。
```http
GET /appinfo_v2
```
响应:
```json
{
  "Os": "Linux",
  "VendorOs": "linux",
  "Kernel": "Linux",
  "Qua": "0",
  "CurrentVersion": "3.2.19-39038",
  "PtVersion": "2.0.0",
  "SsoVersion": 19,
  "PackageName": "com.tencent.qq",
  "WtLoginSdk": "nt.wtlogin.0.0.1",
  "SdkInfo": {
    "SdkBuildTime": 0,
    "SdkVersion": "0",
    "MiscBitMap": 32764,
    "SubSigMap": 0,
    "MainSigMap": 169742560
  },
  "AppId": 1600001615,
  "AppIdQrCode": 537328659,
  "SubAppId": 537328659,
  "AppClientVersion": 39038,
  "NTLoginType": 1
}
```

## 自动 AppInfo 转换

服务器会在加载 AppInfo 文件时自动检测并转换旧版格式为新版格式。
如果检测到旧版格式，将会自动转换并保存为新版格式，同时创建原始文件的备份
（带有 .bak 扩展名）。

### 旧版格式示例:
```json
{
  "Os": "Linux",
  "VendorOs": "linux",
  "Kernel": "Linux",
  "CurrentVersion": "3.2.19-39038",
  "MiscBitmap": 32764,
  "PtVersion": "2.0.0",
  "SsoVersion": 19,
  "PackageName": "com.tencent.qq",
  "WtLoginSdk": "nt.wtlogin.0.0.1",
  "AppId": 1600001615,
  "SubAppId": 537328659,
  "AppIdQrCode": 537328659,
  "AppClientVersion": 39038,
  "MainSigMap": 169742560,
  "SubSigMap": 0,
  "NTLoginType": 1
}
```

### 新版格式示例:
```json
{
  "Os": "Linux",
  "VendorOs": "linux",
  "Kernel": "Linux",
  "Qua": "0",
  "CurrentVersion": "3.2.19-39038",
  "PtVersion": "2.0.0",
  "SsoVersion": 19,
  "PackageName": "com.tencent.qq",
  "WtLoginSdk": "nt.wtlogin.0.0.1",
  "SdkInfo": {
    "SdkBuildTime": 0,
    "SdkVersion": "0",
    "MiscBitMap": 32764,
    "SubSigMap": 0,
    "MainSigMap": 169742560
  },
  "AppId": 1600001615,
  "AppIdQrCode": 537328659,
  "SubAppId": 537328659,
  "AppClientVersion": 39038,
  "NTLoginType": 1
}
```

## 符号问题故障排除

如果遇到错误 `undefined symbol: qq_magic_napi_register`，请尝试以下解决方案：

### 解决方案 1: 检查符号导出
```bash
# 验证符号是否已导出
nm -D sign-server | grep qq_magic_napi_register
```

### 解决方案 2: 使用 LD_PRELOAD（如果解决方案1不起作用）
创建单独的符号文件：
```bash
# 创建 symbols.c 文件
echo '__attribute__((visibility("default"))) void qq_magic_napi_register(void* unused) { }' > symbols.c

# 编译为共享库
gcc -shared -fPIC -o libsymbols.so symbols.c

# 使用 LD_PRELOAD 运行
export LD_PRELOAD=./libsymbols.so
./sign-server -wrapper-path /path/to/wrapper.node
```

## 从 Windows 测试 API

要从 Windows 机器测试 API:

1. 确保 Linux 服务器正在运行且可访问
2. 更新测试脚本中的服务器 IP 地址:
   - `test_api.bat` - 简单的批处理脚本
   - `test_api.ps1` - 功能更强大的 PowerShell 脚本

3. 从 Windows 命令提示符或 PowerShell 运行测试脚本:
   ```cmd
   test_api.bat
   ```
   或
   ```powershell
   .\test_api.ps1
   ```

## 配置说明

服务器使用 `sign.config.toml` 进行配置:

- `preloads`: 预加载的共享库文件数组
  - 示例: `preloads = ["/usr/lib/x86_64-linux-gnu/libgnutls.so.30"]`
  - 通常为空，除非需要特定的系统依赖

- `listen`: 服务器监听的地址和端口
  - 格式: `"主机:端口"`
  - 示例: `"0.0.0.0:8080"` (监听所有接口)
  - 示例: `"127.0.0.1:8080"` (仅监听本地)

- `offset`: 签名函数的内存偏移量
  - 格式: 以 "0x" 开头的十六进制字符串
  - 示例: `"0x5ADE220"`
  - 必须与您的 QQ 客户端版本匹配

- `version`: QQ 版本标识符
  - 格式: `"主版本.次版本.修订版-构建号"`
  - 示例: `"3.2.19-39038"`

- `admin_key`: 管理员密钥，用于 Token 管理 API
  - 字符串值，应更改为安全密钥
  - 示例: `"your_secret_admin_key_here"`

- `token_timeout`: Token 过期时间(秒)
  - 整数值，表示秒数
  - 示例: `3600` (1小时)

## 安全注意事项

1. **更改管理员密钥**: 始终在 `sign.config.toml` 中更改默认管理员密钥
2. **Token 过期**: 设置适当的 Token 超时值
3. **网络安全**: 使用防火墙规则限制对服务器的访问
4. **文件权限**: 确保配置文件具有适当的权限（建议 600）
5. **定期更新**: 保持服务器和依赖项更新

## 许可证

本项目采用 AGPL-3.0 许可证。