#!/bin/bash
# 双击运行（或把 APK 拖到这个文件上）：通过车机应用商店的更新通道安装 APK
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p logs
CMDLOG="logs/sideload-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$CMDLOG") 2>&1
echo "[输出同时保存到 $CMDLOG]"
echo ""

APK=""
if [ $# -ge 1 ] && [ -f "$1" ]; then
  APK="$1"
  shift
fi
if [ -z "$APK" ]; then
  echo "已为你准备好以下配套 APK（位于 artifacts/ 目录）："
  echo "  [1] DiPlay-0.2.22.apk          (默认：开源无线 CarPlay 接收端)"
  echo "  [2] MT-Manager.apk             (MT管理器：打开隐藏应用 / 管理车机文件)"
  echo "  [3] DiscreetLauncher-7.8.4.apk (轻量悬浮抽屉：方便在车机随时呼出第三方应用)"
  echo "  [4] MaterialFiles-1.7.5.apk    (开源文件管理器)"
  echo ""
  read -r -p "输入序号 [1-4]（直接按回车默认选 1），或拖入其他 APK 路径: " CHOICE
  CHOICE="${CHOICE#\'}"; CHOICE="${CHOICE%\'}"
  case "${CHOICE:-1}" in
    1) APK="artifacts/DiPlay-0.2.22.apk" ;;
    2) APK="artifacts/MT-Manager.apk" ;;
    3) APK="artifacts/DiscreetLauncher-7.8.4.apk" ;;
    4) APK="artifacts/MaterialFiles-1.7.5.apk" ;;
    *) APK="$CHOICE" ;;
  esac
fi
if [ ! -f "$APK" ]; then
  echo "找不到 APK：$APK"
  read -r -p "按回车关闭窗口。" _
  exit 1
fi

sudo -p "Mac 管理员密码: " bash scripts/zeekr-sideload.sh --apk "$APK" "$@"
status=$?

echo ""
echo "退出状态：$status"
if [ "$status" != 0 ]; then
  echo "若车机网络异常，运行『停止并恢复.command』。"
fi
read -r -p "按回车关闭窗口。" _
