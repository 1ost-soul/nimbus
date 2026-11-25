#!/usr/bin/env bash
# 停止本项目测试进程（示例脚本，不含任何凭据）
# 用法: ./cleanup.sh <user@host> <远程目录> [本地客户端PID]
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <user@host> <remote-dir> [local-client-pid]" >&2
  exit 2
fi

TARGET="$1"
REMOTE_DIR="$2"
LOCAL_PID="${3:-}"

# 停止 VPS 上的服务端（按 pid 文件精确停止）
ssh "$TARGET" "if [ -f '$REMOTE_DIR/server.pid' ]; then kill \$(cat '$REMOTE_DIR/server.pid') 2>/dev/null || true; fi; sleep 1; ss -tulpn | grep ':44444' || echo REMOTE_PORT_FREE"

# 停止本地客户端
if [ -n "$LOCAL_PID" ]; then
  kill "$LOCAL_PID" 2>/dev/null || true
fi

echo "CLEANUP_DONE"
