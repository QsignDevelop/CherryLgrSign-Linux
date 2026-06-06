#!/usr/bin/env bash
# 在 Debian/Ubuntu 服务器上执行：部署并测试 NekoGelSign（attach 模式）
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "==> 安装构建依赖"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential golang-go libx11-xcb1 libx11-6 libxext6 libgnutls30 curl

echo "==> 编译 sign-server 与 sign_bridge"
go mod tidy
go build -o bin/sign-server .
make -C sign_bridge

QQ_BIN="${QQ_BIN:-}"
if [[ -z "${QQ_BIN}" ]]; then
  for c in /opt/QQ/qq /usr/bin/qq /usr/local/bin/qq; do
    if [[ -x "${c}" ]]; then QQ_BIN="${c}"; break; fi
  done
fi

if [[ -z "${QQ_BIN}" || ! -x "${QQ_BIN}" ]]; then
  echo "WARNING: 未找到 QQ 可执行文件，请安装 Linux QQ 或设置 QQ_BIN"
  echo "  例: export QQ_BIN=/opt/QQ/qq"
else
  echo "==> 使用 QQ: ${QQ_BIN}"
  chmod +x scripts/start-qq-with-bridge.sh
  echo "请先在一个终端启动 QQ（带桥接）："
  echo "  SIGN_OFFSET=$(grep '^offset' sign.config.toml | cut -d= -f2 | tr -d ' \"') \\"
  echo "  QQ_BIN=${QQ_BIN} ./scripts/start-qq-with-bridge.sh"
fi

echo "==> 启动 sign-server（dlopen 模式，自动补环境）"
echo "  ./bin/sign-server -wrapper-path \"${ROOT_DIR}/wrapper.node\" -config sign.config.toml --debug"
echo "  或指定 QQ 安装目录："
echo "  ./bin/sign-server -wrapper-path /opt/QQ/resources/app/wrapper.node -qq-app-dir /opt/QQ/resources/app -config sign.config.toml"

echo ""
echo "测试："
echo "  curl -s http://127.0.0.1:5201/env/status"
echo "  curl -s http://127.0.0.1:5201/attach/status"
echo "  curl -s -X POST http://127.0.0.1:5201/sign -H 'Content-Type: application/json' \\"
echo "    -d '{\"cmd\":\"MessageSvc.PbSendMsg\",\"seq\":12345,\"src\":\"0801120348656C6C6F\"}'"
