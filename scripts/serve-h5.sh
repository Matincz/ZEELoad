#!/usr/bin/env bash
# serve-h5.sh —— 在 Mac 上起一个小 HTTP 服务，让车机浏览器能打开我们的 H5 控制台。
#
#   ./scripts/serve-h5.sh              # 默认 8899 端口、地址 192.168.8.250
#   PORT=8080 IP=192.168.8.8 ./scripts/serve-h5.sh
#
# 车机在另一个 VLAN，但它能连到本机的 443（商店那条链已验证），所以跨网段 HTTP 也通。
# 浏览器每次点击都会打一条 /beacon?... 进来：只看到 tap= 没看到 still= 就是真的跳走了。
set -uo pipefail
cd "$(dirname "$0")/.."
PORT=${PORT:-8899}   # 8000 被本机一个 ssh 隧道占着（还只绑 127.0.0.1，车机进不来）
IP=${IP:-192.168.8.250}
echo "车机浏览器导航里该填： http://$IP:$PORT/"
echo "点击日志会打在这里（Ctrl-C 停）。"
echo
exec python3 -m http.server "$PORT" --bind 0.0.0.0 --directory h5
