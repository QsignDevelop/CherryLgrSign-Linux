# CherryLgrSign Linux

YanXiYu LinuxNT Sign — Linux NTQQ 公益签名服务（Go + CGO）。

## Features

- Auto-detect sign offset (`sub_5BD3EA1` signature scan)
- Auto-detect AppInfo from `major.node` (`QQAppId/`) and `package.json`
- dlopen / attach sign modes
- Runtime environment setup for `wrapper.node`
- No token whitelist required

## Quick Start

```bash
cp sign.config.toml.example sign.config.toml
# Copy wrapper.node, major.node, libbugly.so, libcrbase.so, sharp-lib/ from QQ Linux install

go build -o bin/sign-server .
./bin/sign-server -wrapper-path ./wrapper.node -qq-app-dir /opt/QQ/resources/app
```

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home + stats |
| `/appinfo_v2` | GET | AppInfo JSON |
| `/sign` | POST/GET | Sign request |

### POST /sign

```json
{
  "cmd": "MessageSvc.PbSendMsg",
  "src": "0801120348656C6C6F",
  "seq": 12345
}
```

Response:

```json
{
  "value": {
    "token": "...",
    "extra": "...",
    "sign": "..."
  }
}
```

## Requirements

- Linux x86_64
- Go 1.21+
- gcc (CGO)
- QQ Linux client files (`wrapper.node`, etc.)

See [README_zh.md](README_zh.md) for Chinese documentation.

## License

See [LICENSE](LICENSE).
