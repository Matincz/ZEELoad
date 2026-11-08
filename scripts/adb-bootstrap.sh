#!/usr/bin/env bash
# adb-bootstrap.sh —— 车机连上家里 Wi-Fi 后，一条命令把 adb 打通并把 APK 装进去
#
#   ./scripts/adb-bootstrap.sh                 # 自动在局域网里找车机 → 扫 adb 端口 → 连 → 装
#   ./scripts/adb-bootstrap.sh 192.168.3.33    # 直接指定车机 IP
#   WAIT=10 ./scripts/adb-bootstrap.sh         # 车机还没上电就先等，出现即连
#   APK=artifacts/DiPlay-0.2.22.apk ./scripts/adb-bootstrap.sh
#
# 为什么先扫 5555：Android 9 的 adbd 走 TCP 是明文、不需要配对，端口开着就一条 connect 的事。
# 端口不通也别急着下结论 —— 先确认车机此刻到底连没连 Wi-Fi（本脚本会告诉你）。
set -uo pipefail

ADB=${ADB:-"$HOME/Library/Android/sdk/platform-tools/adb"}
[ -x "$ADB" ] || ADB=$(command -v adb || true)
[ -n "$ADB" ] || { echo "[!!] 找不到 adb：brew install android-platform-tools"; exit 1; }

SITE=${SITE:-default}
GW=${GW:-https://192.168.8.1}
KEY=$(grep -m1 UNIFI_NETWORK_API_KEY "$HOME/.codex/config.toml" 2>/dev/null | cut -d'"' -f2)
CAR_SUBNET=${CAR_SUBNET:-192.168.3.}
PORTS=${PORTS:-"5555 5556 9555 5037"}
APK=${APK:-}
IP=""
SCAN_ONLY=0
for a in "$@"; do
  case "$a" in
    --scan-only) SCAN_ONLY=1 ;;
    *) IP="$a" ;;
  esac
done

# 从路由器问「当前在线终端」，挑出像车机的那台。
# 车机一般没有主机名，所以除了关键字命中，还认 IP 前缀（默认 192.168.3.0/24 = Home 网段）。
find_car() {
  [ -n "$KEY" ] || { echo "  （~/.codex/config.toml 里没有 UniFi 密钥，跳过自动发现）"; return; }
  export STA_JSON
  STA_JSON=$(mktemp) || return
  curl -sk -H "X-API-Key: $KEY" "$GW/proxy/network/api/s/$SITE/stat/sta" -o "$STA_JSON" 2>/dev/null
  python3 <<'PY'
import json, os, re
try:
    rows = (json.load(open(os.environ["STA_JSON"])).get("data") or [])
except Exception:
    rows = []
pat = re.compile(r"zeekr|geely|msmnile|gvmq|vehicle|auto|001|android", re.I)
sub = os.environ.get("CAR_SUBNET", "")
for c in rows:
    ip = str(c.get("ip") or "")
    blob = " ".join(str(c.get(k) or "") for k in ("hostname", "devname", "oui", "name", "user"))
    hit = bool(pat.search(blob))
    if hit or ip.startswith(sub):
        tag = "车机关键字命中" if hit else "仅网段命中"
        print("\t".join([ip, str(c.get("mac") or ""), blob[:36], tag]))
os.unlink(os.environ.get("STA_JSON", ""))
PY
}

echo "== 1. 车机在不在线 =="
if [ -z "$IP" ]; then
  for try in $(seq 1 "${WAIT:-1}"); do
    echo "  问路由器要在线终端列表…"
    MAP=$(CAR_SUBNET="$CAR_SUBNET" find_car)
    [ -n "$MAP" ] && printf '%s\n' "$MAP" | sed 's/^/    /'
    IP=$(printf '%s\n' "$MAP" | awk -F'\t' '$4 ~ /关键字/ {print $1; exit}')
    [ -n "$IP" ] || IP=$(printf '%s\n' "$MAP" | awk -F'\t' '$1 !~ /\.(60|247)$/ {print $1; exit}')
    [ -n "$IP" ] && break
    [ "$try" -lt "${WAIT:-1}" ] && { echo "  还没看到车机，5 秒后重试（$try）…"; sleep 5; }
  done
  [ -n "$IP" ] || { echo "[!!] 路由器上看不到车机。先让车机上电连上 Wi-Fi，或者把 IP 直接传给本脚本。"; exit 1; }
fi
echo "  [ok] 用这个地址继续：$IP"
ping -c 1 -t 2 "$IP" >/dev/null 2>&1 && echo "  [ok] ping 得通" || echo "  [--] ping 不通（车机可能禁 ICMP，不代表端口不通）"

echo
echo "== 2. adb 端口 =="
OPEN=""
for p in $PORTS; do
  if nc -z -G 1 "$IP" "$p" 2>/dev/null; then echo "  [ok] $p 开着"; OPEN="$OPEN $IP:$p"; else echo "  [--] $p 没开"; fi
done
if [ -z "$OPEN" ]; then
  cat <<EOF
[!!] 没有 adb 端口在听。Android 9 上 adbd 只在这两种情况下才会开：
      A) 车机上开了「网络 ADB / ADB 调试」——一般在 设置→关于→连点版本号，或工程模式里
      B) 插 USB 数据线、车机作为 USB device（前排 C 口不一定支持，值得试一根）
    打通任意一条后重跑本脚本，端口一通后面全是自动的。
EOF
  exit 1
fi
[ "$SCAN_ONLY" = 1 ] && { echo "(--scan-only) 到此为止"; exit 0; }

echo
echo "== 3. 连接 =="
for EP in $OPEN; do
  echo "  adb connect $EP"
  "$ADB" connect "$EP" 2>&1 | sed 's/^/    /'
done
"$ADB" devices | sed 's/^/    /'
DEV=$(printf '%s\n' $OPEN | head -1)
"$ADB" -s "$DEV" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r' | sed 's/^/    Android  /'
"$ADB" -s "$DEV" shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r' | sed 's/^/    ABI      /'

echo
echo "== 4. 装 APK =="
if [ -z "$APK" ]; then
  echo "  （没指定 APK，跳过。下一步：APK=artifacts/DiPlay-0.2.22.apk $0 $IP）"
  echo "  注：adb install 完全绕过应用商店那套哈希鉴权，也不用管「未知来源」——一步到位。"
else
  [ -f "$APK" ] || { echo "[!!] APK 不存在：$APK"; exit 1; }
  echo "  adb -s $DEV install -r -t $APK"
  "$ADB" -s "$DEV" install -r -t "$APK" 2>&1 | sed 's/^/    /'
fi
