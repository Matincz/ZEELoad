#!/bin/bash
# 极载 ZEEload · 车机透明代理（macOS）
#
# 作用：
#   1. 只把「车机 -> 目标域名当前解析出的 IP:443」或（--all-443）「车机 -> 任意 IP:443」
#      的 TCP 流量重定向到本机 mitmdump；
#   2. mitmdump 以透明模式 + 内置 --emudhra 证书链解密，其余域名按 --allow-hosts 直接透传；
#   3. 退出（Ctrl-C / 报错）时自动卸载 pf 规则并停止 mitmdump。
#
# 不修改 /etc/pf.conf，不替换主规则集，只操作独立 anchor：com.apple/zeekr-capture
#
# 用法：
#   sudo bash scripts/transparent-test.sh [--all-443] [--reset-states] [--check-only]
#
# 环境变量覆盖：ZEEKR_IFACE ZEEKR_CAR_IP ZEEKR_CAR_MAC ZEEKR_LISTEN_IP ZEEKR_PORT ZEEKR_VENV

set -uo pipefail
umask 077

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE=$(cd "$SCRIPT_DIR/.." && pwd)
VENV=${ZEEKR_VENV:-}
MITMDUMP=""
ADDON=$BASE/addons/zeekr_log.py

IFACE=${ZEEKR_IFACE:-}
CAR_IP=${ZEEKR_CAR_IP:-}
CAR_MAC=${ZEEKR_CAR_MAC:-}
LISTEN_IP=${ZEEKR_LISTEN_IP:-127.0.0.1}
PORT=${ZEEKR_PORT:-18081}
ANCHOR=${ZEEKR_ANCHOR:-com.apple/zeekr-capture}
DOMAINS=${ZEEKR_DOMAINS:-"snc-api-gw.zeekrlife.com snc-download-cdn.zeekrlife.com"}
HOSTS=${ZEEKR_HOSTS:-zeekrlife.com}

MODE=targets
RESET_STATES=0
CHECK_ONLY=0

CORRUPT=-1
FAKE_HASH=0
FAKE_SIGN=0
REPLACE_APK=""
INJECT_PKG=""
INTERCEPT_ALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --all-443) MODE=all443; shift ;;
    --reset-states) RESET_STATES=1; shift ;;
    --fake-hash) FAKE_HASH=1; shift ;;
    --fake-sign) FAKE_SIGN=1; shift ;;
    --intercept-all) INTERCEPT_ALL=1; shift ;;
    --domains)
      [ $# -ge 2 ] || { echo "--domains 需要空格分隔的域名列表" >&2; exit 2; }
      DOMAINS=$2; shift 2 ;;
    --hosts)
      [ $# -ge 2 ] || { echo "--hosts 需要逗号分隔的域名后缀" >&2; exit 2; }
      HOSTS=$2; shift 2 ;;
    --inject-update)
      [ $# -ge 2 ] || { echo "--inject-update 需要包名" >&2; exit 2; }
      INJECT_PKG=$2; shift 2 ;;
    --replace-apk)
      [ $# -ge 2 ] || { echo "--replace-apk 需要 APK 路径" >&2; exit 2; }
      REPLACE_APK=$2; shift 2 ;;
    --check-only) CHECK_ONLY=1; shift ;;
    --corrupt)
      [ $# -ge 2 ] || { echo "--corrupt 需要偏移字节数" >&2; exit 2; }
      case "$2" in ''|*[!0-9]*) echo "--corrupt 参数必须是整数" >&2; exit 2 ;; esac
      CORRUPT=$2; shift 2 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }

# ---- mitmproxy 定位 ----
if [ -n "$VENV" ]; then
  MITMDUMP=$VENV/bin/mitmdump
elif [ -x "$BASE/venv/bin/mitmdump" ]; then
  VENV=$BASE/venv; MITMDUMP=$VENV/bin/mitmdump
elif have mitmdump; then
  MITMDUMP=$(command -v mitmdump)
elif [ -x "$HOME/.mitmproxy-venv/bin/mitmdump" ]; then
  VENV=$HOME/.mitmproxy-venv
  MITMDUMP=$VENV/bin/mitmdump
fi

# ---- 自动探测：共享接口 / 车机 ----

detect_iface() {
  # 优先选择有 IPv4 私有地址且状态 active 的 bridge（macOS 互联网共享会建 bridge100）
  local cand addr status best=""
  for cand in $(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^bridge'); do
    addr=$(ifconfig "$cand" 2>/dev/null | awk '/inet /{print $2; exit}')
    [ -n "$addr" ] || continue
    case "$addr" in
      192.168.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;;
      *) continue ;;
    esac
    status=$(ifconfig "$cand" 2>/dev/null | awk '/status:/{print $2; exit}')
    if [ "$status" = "active" ]; then
      if ifconfig "$cand" 2>/dev/null | grep -q 'member: ap'; then
        echo "$cand"; return
      fi
      best="${best:-$cand}"
    fi
  done
  echo "$best"
}

iface_ip() {
  ifconfig "$1" 2>/dev/null | awk '/inet /{print $2; exit}'
}

iface_prefix() {
  # 返回 /24 前缀，例如 192.168.2.
  local ip
  ip=$(iface_ip "$1")
  [ -n "$ip" ] || return
  echo "${ip%.*}."
}

# 从 /var/db/dhcpd_leases 里找车机（按名称关键字，其次唯一租约）
detect_lease() {
  local prefix="$1" mode="$2"
  [ -r /var/db/dhcpd_leases ] || return
  awk -v prefix="$prefix" -v mode="$mode" '
    /^\{/ { name=""; ip=""; hw=""; next }
    /name=/ { sub(/.*name=/, ""); name=$0 }
    /ip_address=/ { sub(/.*ip_address=/, ""); ip=$0 }
    /hw_address=/ { sub(/.*hw_address=/, ""); hw=$0 }
    /^\}/ {
      if (ip ~ ("^" prefix)) {
        wanted = (name ~ /(auto|ivt|evb|zeekr|lynk|ecarx|dhu|headunit|hu)/)
        if (mode == "ip" && wanted) print ip
        if (mode == "ip") count++
        if (mode == "name" && wanted) print name
        if (mode == "mac" && wanted) {
          n=split(hw, parts, ","); s=parts[n];
          m=split(s, oct, ":"); if (m >= 6) printf "%s:%s:%s:%s:%s:%s\n", oct[m-5], oct[m-4], oct[m-3], oct[m-2], oct[m-1], oct[m]
        }
      }
    }
  ' /var/db/dhcpd_leases
}

say() { printf '%s\n' "$*"; }
warn() { printf '警告：%s\n' "$*" >&2; }
die() { printf '错误：%s\n' "$*" >&2; exit 1; }
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=$BASE/logs/$STAMP
RULEFILE=$OUT/rdr.conf
LOG=$OUT/mitm.log
FLOW=$OUT/flows.mitm
CLEANED=0
PROXY_STARTED=0
RULES_LOADED=0

cleanup() {
  [ "$CLEANED" = 1 ] && return
  CLEANED=1
  trap - EXIT INT TERM HUP
  say ""
  say "================ 清理 ================"

  # 先卸载转发规则，再停代理（顺序与交接文档一致）
  if [ "$RULES_LOADED" = 1 ]; then
    # 卸载前记录规则计数器：Evaluations=0 说明 wildcard anchor 没被求值；Packets=0 说明没有命中
    NATV=$(pfctl -a "$ANCHOR" -s nat -v 2>&1)
    RULEV=$(pfctl -a "$ANCHOR" -s rules -v 2>&1)
    {
      echo "## $(date) anchor 计数器（flush 前）"
      echo "### nat -v"; printf '%s\n' "$NATV"
      echo "### rules -v"; printf '%s\n' "$RULEV"
    } > "$OUT/pf-after.txt" 2>&1
    HIT=$(printf '%s\n' "$NATV" | grep -o 'Packets: [0-9]*' | awk '{s+=$2} END{print s+0}')
    EVAL=$(printf '%s\n' "$NATV" | grep -o 'Evaluations: [0-9]*' | awk '{s+=$2} END{print s+0}')
    say "pf 计数器：求值 ${EVAL} 次，命中 ${HIT} 个包（明细见 pf-after.txt）"
    if [ "${EVAL:-0}" = 0 ]; then
      warn "anchor 规则从未被求值：主规则集的 wildcard anchor 可能未生效，需改用其他挂接方式"
    elif [ "${HIT:-0}" = 0 ]; then
      warn "anchor 被求值但没有包命中：车机 IP/目标 IP 可能变化，可试 --all-443"
    fi
    if pfctl -a "$ANCHOR" -F all 2>/dev/null; then
      if pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep -q .; then
        warn "anchor $ANCHOR 仍有规则；请手动执行：sudo pfctl -a $ANCHOR -F all"
      else
        say "[ok] 已卸载 pf 转发规则（${ANCHOR}）"
      fi
    else
      warn "卸载 anchor 失败；请手动执行：sudo pfctl -a $ANCHOR -F all"
    fi
  fi

  if [ "$PROXY_STARTED" = 1 ]; then
    pkill -f "$FLOW" 2>/dev/null && say "[ok] 已停止 mitmdump"
  fi

  # root 创建的产物交还给执行 sudo 的用户
  if [ -n "${SUDO_UID:-}" ]; then
    chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$BASE/logs" "$BASE/mitm-config" 2>/dev/null
  fi

  say ""
  say "本次输出目录：$OUT"
  say "  $OUT/mitm.log    mitmdump 日志（TLS 错误、连接、请求行）"
  say "  $OUT/requests.jsonl  目标域名请求/响应元数据"
  say "  $OUT/downloads/      响应体（含 APK，带 sha256 前缀）"
  say "  $OUT/flows.mitm      完整 mitmproxy flow（可用 mitmweb 打开复查）"
  say "  $OUT/pf-before.txt   测试前 pf 状态快照"
  say "  $OUT/rdr.conf        本次加载的 pf 规则"
  say "  $OUT/pf-after.txt    anchor 计数器（求值/命中）"
  say "====================================="
}
trap cleanup EXIT
trap 'say ""; say "收到中断信号，准备清理…"; exit 130' INT TERM HUP

# ---------------------------------------------------------------- 预检

if [ "$CHECK_ONLY" = 0 ]; then
  [ "$(id -u)" = 0 ] || die "需要管理员权限。请用：sudo bash $0"
fi

# ---- 自动探测 ----
if [ -z "$IFACE" ]; then
  IFACE=$(detect_iface)
  [ -n "$IFACE" ] || die "找不到正在共享的 bridge 接口；请确认已开启互联网共享，或用 ZEEKR_IFACE 指定"
fi
PREFIX=$(iface_prefix "$IFACE")
if [ -z "$CAR_IP" ] && [ "$CHECK_ONLY" = 0 -o "$CHECK_ONLY" = 1 ]; then
  CAR_IP=$(detect_lease "$PREFIX" ip | head -1)
fi
if [ -z "$CAR_MAC" ] && [ -n "$CAR_IP" ]; then
  CAR_MAC=$(detect_lease "$PREFIX" mac | head -1)
fi

[ -x "$MITMDUMP" ] || die "找不到可执行的 mitmdump：${MITMDUMP}（可用 ZEEKR_VENV 覆盖）"
[ -f "$ADDON" ] || die "找不到 addon：$ADDON"

mkdir -p "$OUT" "$BASE/mitm-config"
if [ -n "${SUDO_UID:-}" ]; then chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT" 2>/dev/null; fi

say "== 环境预检 =="
say "接口：$IFACE    车机：$CAR_IP ($CAR_MAC)    监听：$LISTEN_IP:$PORT"

IFACE_ADDR=$(ifconfig "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}')
[ -n "$IFACE_ADDR" ] || die "接口 $IFACE 没有 IPv4 地址；请确认系统互联网共享已开启"
say "[ok] $IFACE = $IFACE_ADDR"
say "[ok] mitmdump: $MITMDUMP"

if arp -n "$CAR_IP" 2>/dev/null | grep -qi "$CAR_MAC"; then
  say "[ok] ARP 中 $CAR_IP 对应 $CAR_MAC"
else
  warn "ARP 中没有 $CAR_IP -> ${CAR_MAC}。车机可能使用新 IP 或未连接；请先运行 scripts/check-environment.sh"
fi

if ping -c 1 -t 2 "$CAR_IP" >/dev/null 2>&1; then
  say "[ok] 车机 $CAR_IP 可 ping 通"
else
  warn "ping $CAR_IP 失败；若车机确实在线可忽略（部分设备禁 ping）"
fi

PORT_HOLDER=$(lsof -nP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $1" pid="$2}')
if [ -n "$PORT_HOLDER" ]; then
  die "端口 $PORT 已被占用：$PORT_HOLDER"
fi

if [ "$CHECK_ONLY" = 1 ] && [ "$(id -u)" != 0 ]; then
  warn "check-only 且未使用 root：跳过 pf 检查（pfctl 需要管理员权限）。"
else
  say "[..] 检查 pf 状态与主规则集"
  PF_INFO=$(pfctl -s info 2>&1) || die "无法读取 pf：${PF_INFO}（需要 root）"
  if printf '%s' "$PF_INFO" | grep -q "Status: Enabled"; then
    say "[ok] pf 已启用"
  else
    die "pf 未启用；互联网共享应已启用 pf，请先检查系统共享状态，不要在此状态下继续"
  fi

  # 注意：rdr-anchor 出现在 pfctl -s nat 的输出里，不在 -s rules 里
  PF_NAT=$(pfctl -s nat 2>&1) || die "无法读取 pf nat 规则：$PF_NAT"
  if printf '%s' "$PF_NAT" | grep -q 'rdr-anchor "com.apple/\*"'; then
    say "[ok] pf 规则集包含 rdr-anchor \"com.apple/*\"（新 anchor 会被求值）"
  else
    say "当前 nat 规则如下："
    printf '%s\n' "$PF_NAT" | sed 's/^/    /'
    die "pf 规则集没有 rdr-anchor \"com.apple/*\"，无法在不改主规则集的前提下挂接转发规则。
请把上面的 nat 规则发我，改用其他挂接方式。"
  fi

  # pf 快照，便于事后对比或回滚参考
  {
    echo "# $(date) 测试前 pf 状态"
    echo "## pfctl -s info";   pfctl -s info 2>&1
    echo "## pfctl -s rules";  pfctl -s rules 2>&1
    echo "## pfctl -s nat";    pfctl -s nat 2>&1
    echo "## pfctl -s Anchors"; pfctl -s Anchors 2>&1
    echo "## pfctl -s Tables"; pfctl -s Tables 2>&1
    echo "## pfctl -s Limits"; pfctl -s Limits 2>&1
  } > "$OUT/pf-before.txt" 2>&1
  say "[ok] pf 快照：$OUT/pf-before.txt"
fi

# CDN 有 AAAA 记录：车机若走 IPv6 会完全绕开 IPv4 转发，因此把目标域名的 IPv6 地址
# 用 block return 打回去，迫使客户端回退到 IPv4（本脚本只转发 IPv4）。
V6=""
for d in $DOMAINS; do
  if have dig; then
    v6s=$(dig +short AAAA "$d" 2>/dev/null | grep -E '^[0-9a-fA-F:]+$')
  else
    v6s=""
  fi
  V6="$V6 $v6s"
done
V6=$(printf '%s\n' $V6 | sort -u)

case "$MODE" in
  targets)
    say "[..] 解析目标域名"
    RESOLVED=""
    for d in $DOMAINS; do
      if have dig; then
        ips=$(dig +short A "$d" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
      elif have host; then
        ips=$(host -t A "$d" 2>/dev/null | awk '/has address/{print $NF}')
      else
        ips=$(dscacheutil -q host -a name "$d" 2>/dev/null | awk '/^ip_address:/{print $2}')
      fi
      if [ -z "$ips" ]; then die "解析 $d 失败；请确认 Mac 当前可上网"; fi
      say "  $d:"; for ip in $ips; do say "    $ip"; done
      RESOLVED="$RESOLVED $ips"
    done
    RESOLVED=$(printf '%s\n' $RESOLVED | sort -u)
    ;;
  all443)
    say "[..] 范围：车机所有 TCP 443（非 zeekrlife 域名按 SNI 透传，不解密）"
    RESOLVED=""
    ;;
esac

# ---------------------------------------------------------------- 生成规则

{
  echo "# 极载 ZEEload 透明转发规则（由 transparent-test.sh 生成，${STAMP}）"
  echo "# 仅作用于车机 ${CAR_IP}，来自接口 ${IFACE}，目标 TCP 443"
  SRC=${CAR_IP:-${PREFIX}0/24}
  if [ "$MODE" = all443 ]; then
    echo "rdr pass on $IFACE inet proto tcp from $SRC to any port 443 -> $LISTEN_IP port $PORT"
  else
    for ip in $RESOLVED; do
      echo "rdr pass on $IFACE inet proto tcp from $SRC to $ip port 443 -> $LISTEN_IP port $PORT"
    done
  fi
  if [ -n "$V6" ]; then
    echo "# 目标域名的 IPv6 地址：直接拒绝，让客户端回退 IPv4（否则会绕过转发）"
    for ip in $V6; do
      echo "block return quick on $IFACE inet6 proto tcp from any to $ip port 443"
    done
  fi
} > "$RULEFILE"

say ""
say "== 将要加载的 pf 规则（anchor: ${ANCHOR}）=="
cat "$RULEFILE"

if [ "$CHECK_ONLY" = 1 ]; then
  say ""
  say "check-only：未加载规则，未启动代理。"
  exit 0
fi

# ---------------------------------------------------------------- 加载规则

say ""
say "[..] 加载 anchor 规则"
if ! pfctl -a "$ANCHOR" -f "$RULEFILE" 2>"$OUT/pf-load.err"; then
  cat "$OUT/pf-load.err" >&2
  die "加载 anchor 失败（见上方错误）"
fi
RULES_LOADED=1
if ! pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep -q .; then
  warn "anchor 已加载但读不到规则，请检查 pf；继续前建议先停止"
fi
say "[ok] 已加载："
pfctl -a "$ANCHOR" -s rules 2>/dev/null | sed 's/^/    /'

if [ "$RESET_STATES" = 1 ]; then
  pfctl -k "$CAR_IP" 2>/dev/null && say "[ok] 已清除车机旧连接状态（会强制重连）"
fi

# ---------------------------------------------------------------- 启动代理

if [ -n "$REPLACE_APK" ]; then
  say ""
  say "!! 替换模式：所有 .apk 下载内容替换为 $REPLACE_APK"
  say "!! 元数据里的 sha256/apkMd5 同步改写为该文件的值（$(shasum -a 256 "$REPLACE_APK" | cut -c1-12)…）"
  say "!! 注入目标包：${INJECT_PKG:-无}（检查更新列表里会看到一条更高版本）"
  say "!! 服务端会因为没有官方哈希而返回 sign=null，观察商店是否仍继续安装"
fi

if [ "$FAKE_SIGN" = 1 ]; then
  say ""
  say "!! 调试模式：/app/signature 返回的 sign 会被换成等长随机值"
  say "!! 目的：判断 sign 是否真的被商店/安装器校验；官方内容照常下载"
fi

if [ "$FAKE_HASH" = 1 ]; then
  say ""
  say "!! 调试模式：appList 里的 sha256/apkMd5 会被改写成等长伪造值（其余字段不变）"
  say "!! 目的：观察 /app/signature 是否给非官方哈希签名；下载会因哈希不符失败，属正常"
fi

if [ "$CORRUPT" -ge 0 ]; then
  say ""
  say "!! 调试模式：APK 下载数据中会翻转 1 个字节（长度不变、仍为流式转发）"
  say "!! 目的：判断商店/安装器是否校验下载内容的哈希；预期安装会失败，属正常"
fi

say ""
say "== 启动 mitmdump（透明模式 + --emudhra）=="
say "现在请在车机打开应用商店并触发同一个官方应用的下载。"
say "按 Ctrl-C 结束本次测试（会先卸载规则再停止代理）。"
say ""

MITM_ARGS=(
  --mode transparent
  --emudhra
  --listen-host "$LISTEN_IP"
  --listen-port "$PORT"
  --set "confdir=$BASE/mitm-config"
  --set stream_large_bodies=2m
  --set "zeekr_corrupt_offset=$CORRUPT"
  -s "$ADDON"
  --set "zeekr_out=$OUT"
  -w "$FLOW"
)

if [ "$INTERCEPT_ALL" = 0 ]; then
  HOST_RE=$(printf '%s' "$HOSTS" | tr ',' '|')
  MITM_ARGS+=(--allow-hosts "$HOST_RE")
fi
MITM_ARGS+=(--set "zeekr_hosts=$HOSTS")

if [ "$FAKE_HASH" = 1 ]; then
  MITM_ARGS+=(--set zeekr_fake_hash=true)
fi
if [ "$FAKE_SIGN" = 1 ]; then
  MITM_ARGS+=(--set zeekr_fake_sign=true)
fi
if [ -n "$REPLACE_APK" ]; then
  [ -f "$REPLACE_APK" ] || die "替换用的 APK 不存在：$REPLACE_APK"
  REPL_SHA=$(shasum -a 256 "$REPLACE_APK" | awk '{print $1}')
  REPL_MD5=$(md5 -q "$REPLACE_APK")
  MITM_ARGS+=(
    --set "zeekr_inject_pkg=$INJECT_PKG"
    --set "zeekr_replace_apk=$REPLACE_APK"
    --set "zeekr_override_sha256=$REPL_SHA"
    --set "zeekr_override_md5=$REPL_MD5"
  )
fi

export PYTHONUNBUFFERED=1
"$MITMDUMP" "${MITM_ARGS[@]}" 2>&1 | tee -a "$LOG" &
PROXY_STARTED=1
PROXY_WAIT=$!

# 给进程几秒启动时间，确认监听成功再提示
sleep 3
if ! pgrep -f "$FLOW" >/dev/null 2>&1; then
  say "mitmdump 启动失败，日志如下："
  tail -n 40 "$LOG" 2>/dev/null
  die "代理未运行，已回滚"
fi
if have lsof; then
  n=0
  until lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; do
    n=$((n + 1))
    [ "$n" -ge 5 ] && { warn "端口 $PORT 未见监听，请检查日志：$LOG"; break; }
    sleep 1
  done
fi
say "[ok] mitmdump 已启动，监听 $LISTEN_IP:$PORT"

echo "start=$(date)" >> "$OUT/summary.txt"
echo "iface=$IFACE car=$CAR_IP mac=$CAR_MAC listen=$LISTEN_IP:$PORT mode=$MODE" >> "$OUT/summary.txt"
echo "domains=$DOMAINS" >> "$OUT/summary.txt"
echo "resolved=$(printf '%s' "$RESOLVED" | tr '\n' ' ')" >> "$OUT/summary.txt"
echo "anchor=$ANCHOR" >> "$OUT/summary.txt"
echo "corrupt_offset=$CORRUPT" >> "$OUT/summary.txt"
echo "fake_hash=$FAKE_HASH" >> "$OUT/summary.txt"
echo "fake_sign=$FAKE_SIGN" >> "$OUT/summary.txt"
echo "replace_apk=$REPLACE_APK" >> "$OUT/summary.txt"
echo "inject_pkg=$INJECT_PKG" >> "$OUT/summary.txt"
echo "intercept_all=$INTERCEPT_ALL" >> "$OUT/summary.txt"
echo "domains=$DOMAINS" >> "$OUT/summary.txt"
echo "hosts=$HOSTS" >> "$OUT/summary.txt"
echo "mitmdump_args=${MITM_ARGS[*]}" >> "$OUT/summary.txt"

wait "$PROXY_WAIT"
echo "stop=$(date)" >> "$OUT/summary.txt"
exit 0
