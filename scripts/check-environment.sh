#!/bin/bash
# 只读环境检查（不需要管理员密码）。在接车机前后各跑一次。
# 用法：bash scripts/check-environment.sh

set -uo pipefail
BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [ -n "${ZEEKR_VENV:-}" ]; then
  MITMDUMP=$ZEEKR_VENV/bin/mitmdump
elif [ -x "$BASE/venv/bin/mitmdump" ]; then
  MITMDUMP=$BASE/venv/bin/mitmdump
else
  MITMDUMP=$(command -v mitmdump 2>/dev/null || echo mitmdump)
fi
PORT=${ZEEKR_PORT:-18081}
DOMAINS=${ZEEKR_DOMAINS:-"snc-api-gw.zeekrlife.com snc-download-cdn.zeekrlife.com"}

# 自动探测：共享接口（bridge*）与车机（DHCP 租约按名称识别）
detect_iface() {
  local cand addr status best=""
  for cand in $(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^bridge'); do
    addr=$(ifconfig "$cand" 2>/dev/null | awk '/inet /{print $2; exit}')
    [ -n "$addr" ] || continue
    case "$addr" in 192.168.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;; *) continue ;; esac
    status=$(ifconfig "$cand" 2>/dev/null | awk '/status:/{print $2; exit}')
    if [ "$status" = "active" ]; then
      ifconfig "$cand" 2>/dev/null | grep -q 'member: ap' && { echo "$cand"; return; }
      best="${best:-$cand}"
    fi
  done
  echo "$best"
}

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
        if (mode == "mac" && wanted) { n=split(hw, p, ","); s=p[n]; m=split(s, o, ":");
          if (m >= 6) printf "%s:%s:%s:%s:%s:%s\n", o[m-5], o[m-4], o[m-3], o[m-2], o[m-1], o[m] }
      }
    }
  ' /var/db/dhcpd_leases
}

IFACE=${ZEEKR_IFACE:-$(detect_iface)}
prefix=""
if [ -n "$IFACE" ]; then
  prefix=$(ifconfig "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}' | sed 's/\.[0-9]*$/\./')
fi
CAR_IP=${ZEEKR_CAR_IP:-}
CAR_MAC=${ZEEKR_CAR_MAC:-}
if [ -n "$prefix" ]; then
  CAR_IP=${CAR_IP:-$(detect_lease "$prefix" ip | head -1)}
  CAR_MAC=${CAR_MAC:-$(detect_lease "$prefix" mac | head -1)}
fi

say() { printf '%s\n' "$*"; }
ok() { printf '[ok] %s\n' "$*"; }
bad() { printf '[!!] %s\n' "$*"; }

say "== 时间 =="; date
say ""
say "== 工具 =="
if [ -x "$MITMDUMP" ]; then
  ok "mitmdump: $("$MITMDUMP" --version 2>&1 | head -1)"
  grep -q -- '--emudhra' <("$MITMDUMP" --help 2>&1) && ok "支持 --emudhra" || bad "当前 mitmdump 不支持 --emudhra"
else
  bad "找不到 $MITMDUMP"
fi
[ -f "$BASE/addons/zeekr_log.py" ] && ok "addon 存在" || bad "缺少 addons/zeekr_log.py"

say ""
say "== 接口与地址 =="
if [ -z "$IFACE" ]; then
  bad "未检测到共享接口：请先开启「互联网共享」，或用 ZEEKR_IFACE 指定"
else
  ifconfig "$IFACE" 2>/dev/null | awk '/inet /{print "  '"$IFACE"' -> " $2}'
fi
gw=$(netstat -rn -f inet 2>/dev/null | awk '$1=="default" && $4 ~ /^en/ {print $2" via "$4; exit}')
say "  默认路由：${gw:-未找到}"
say "  热点 DHCP 配置（/etc/bootpd.plist）中的 DNS："
grep -A2 dhcp_domain_name_server /etc/bootpd.plist 2>/dev/null | grep string | sed 's/^/    /'

say ""
say "== 车机 =="
if arp -n "$CAR_IP" 2>/dev/null | grep -qi "$CAR_MAC"; then
  ok "ARP：$CAR_IP -> $CAR_MAC"
else
  bad "ARP 中没有 $CAR_IP -> ${CAR_MAC}（车机 IP 可能变化）"
  arp -an | grep '192\.168\.2\.' | sed 's/^/  /'
fi
ping -c 1 -t 2 "$CAR_IP" >/dev/null 2>&1 && ok "ping $CAR_IP 通" || bad "ping $CAR_IP 失败"

say ""
say "== 目标域名解析（Mac 侧，车机使用 $IFACE 上的地址作为 DNS）=="
for d in $DOMAINS; do
  say "  $d:"
  if command -v dig >/dev/null 2>&1; then
    dig +short A "$d" 2>/dev/null | grep -E '^[0-9]+\.' | sed 's/^/    /'
  else
    host -t A "$d" 2>/dev/null | awk '/has address/{print "    "$NF}'
  fi
done

say ""
say "== LAN + UniFi DNS 劫持判据（当前主线：域名必须解析到本机）=="
MYIPS=$(ifconfig 2>/dev/null | awk '/inet (192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/{print $2}' | sort -u)
GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}')
[ -n "$GW" ] || GW=$(netstat -rn -f inet 2>/dev/null | awk '$1=="default"{print $2; exit}')
# 本机常有好几个地址（虚拟网卡/容器网段），只有和网关同网段那个能被车机连到
GWPREFIX=${GW%.*}
SAME=""; OTHER=""
if [ -n "$GWPREFIX" ]; then
  SAME=$(echo "$MYIPS" | grep "^$GWPREFIX\." | tr '\n' ' ' | sed 's/ *$//')
  OTHER=$(echo "$MYIPS" | grep -v "^$GWPREFIX\." | tr '\n' ' ' | sed 's/ *$//')
fi
# 默认路由那块网卡上的地址就是车机连过来的那个（lan_sideload 监听 0.0.0.0，所以同网段的其他地址也能用）
DEF_IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')
PRIMARY=$(ifconfig "${DEF_IF:-none}" 2>/dev/null | awk '/inet /{print $2; exit}')
case " $SAME " in
  *" $PRIMARY "*) HINT_IP="$PRIMARY" ;;
  *) HINT_IP=$(echo "$SAME" | awk '{print $1}'); [ -n "$HINT_IP" ] || HINT_IP=$(echo "$MYIPS" | awk 'NR==1') ;;
esac
say "  网关（车机的 DNS 服务器）：${GW:-未找到}"
# 注：这里不用 ${VAR:+中文} 那种写法——C locale 下 bash 会把多字节字符的首字节当成变量名的一部分
if [ -n "$SAME" ]; then
  say "  本机可用地址（与网关同网段）：$SAME"
else
  say "  本机可用地址：一个也没有（本机不在网关网段上？）"
fi
[ -n "$PRIMARY" ] && say "      车机连过来的就是默认路由 $DEF_IF 上的 $PRIMARY"
[ -n "$OTHER" ] && say "  其它网卡（虚拟网段，车机连不到）：$OTHER"
HIJACK=1
for d in $DOMAINS; do
  got=$(dig +short +time=3 +tries=1 "$d" 2>/dev/null | grep -E '^[0-9]+\.' || true)
  gotgw=""
  [ -n "$GW" ] && gotgw=$(dig +short +time=3 +tries=1 @"$GW" "$d" 2>/dev/null | grep -E '^[0-9]+\.' || true)
  hit=0
  for a in $got $gotgw; do
    echo "$MYIPS" | grep -qx "$a" && hit=1
  done
  if [ "$hit" = 1 ]; then
    ok "$d 已解析到本机 → 车机流量会到我们"
  else
    HIJACK=0
    bad "$d 还没指向本机：本机解析 [$(echo $got | tr '\n' ' ')] / 网关解析 [$(echo $gotgw | tr '\n' ' ')]"
  fi
done
# 本地 DNS 记录可能只下发到部分网络（车机和 Mac 不在同一个 VLAN 时就不同步），
# 所以权威判据是：看看 443 上有没有非本机的连接进来了
# 只数「本地端口是 443」的那些（否则会把自己机器连出去到别人 443 的连接也算进来）
PEERS=$(netstat -an -p tcp 2>/dev/null | awk '$4 ~ /\.443$/ && $6 == "ESTABLISHED" {split($5,a,"."); if (length(a)==5) print a[1]"."a[2]"."a[3]"."a[4]}' | sort -u)
OUTSIDE=""
for p in $PEERS; do
  case "$p" in 127.*|""|::*) continue ;; esac
  echo "$MYIPS" | grep -qx "$p" || OUTSIDE="$OUTSIDE $p"
done
if [ -n "$OUTSIDE" ]; then
  ok "443 上已有外部设备连进来：$(echo $OUTSIDE | tr '\n' ' ')（这才是劫持生效的硬证据）"
  HIJACK=1
fi
if [ "$HIJACK" = 0 ]; then
  say "  → 也可能是本地记录只下发到车机那个网络（Mac 自己问不到很正常）。"
  say "    权威判据：启服务后看日志里有没有 'SNI-443 收到来自 <车机IP>'；有就是通的。"
  say "  → 若确实没生效，就别在车上点：商店会直接连真服务器，日志里什么都看不到。"
  say "    去 UniFi 把这些域名加一条 A 记录指到 $HINT_IP（并确认站点开了 Local DNS），"
  say "    加完重跑本脚本确认变 [ok]，再让车机去点商店。"
  say "    注：改写是整站点生效，手机上不信任我们证书的极氪 App 这段时间会连不上；跑完删记录即恢复。"
fi

say ""
say "== 端口与进程 =="
if command -v lsof >/dev/null 2>&1; then
  if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    bad "端口 $PORT 已被占用："
    lsof -nP -iTCP:"$PORT" -sTCP:LISTEN | sed 's/^/  /'
  else
    ok "端口 $PORT 空闲"
  fi
  # LAN 路线下车机直连 443，没人接就是白跑一轮
  if lsof -nP -iTCP:443 -sTCP:LISTEN >/dev/null 2>&1; then
    ok "端口 443 已有人监听（LAN 路线必需）："
    lsof -nP -iTCP:443 -sTCP:LISTEN | sed 's/^/  /'
  else
    bad "端口 443 没人监听：LAN 路线下要先跑 lan_sideload.py 占住 443，否则劫持过来的连接会直接失败"
  fi
fi
pgrep -fl 'mitmdump' | sed 's/^/  /' || ok "没有运行中的 mitmdump"

say ""
say "== 权限提示 =="
if /sbin/pfctl -s info >/dev/null 2>&1; then
  ok "当前用户可读 pf（少见）"
else
  say "  pfctl 需要管理员权限：透明转发测试请用 sudo 运行 scripts/transparent-test.sh"
fi
