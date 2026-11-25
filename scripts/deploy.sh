#!/usr/bin/env bash
# 部署服务端（示例脚本，不含任何凭据）
# 用法: ./deploy.sh <本地二进制> <user@host> <远程目录> <远程配置文件>
# SSH 密码由 ssh/scp 交互式提示或 SSH agent 提供，脚本不保存凭据。
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <local-binary> <user@host> <remote-dir> <remote-config>" >&2
  exit 2
fi

BIN="$1"
TARGET="$2"
REMOTE_DIR="$3"
REMOTE_CFG="$4"

[ -f "$BIN" ] || { echo "binary not found: $BIN" >&2; exit 2; }

# 1. 读取旧 PID 并精确停止，避免误杀其他服务
ssh "$TARGET" "if [ -f '$REMOTE_DIR/server.pid' ]; then kill \$(cat '$REMOTE_DIR/server.pid') 2>/dev/null || true; fi; sleep 2"

# 2. 上传二进制与配置
ssh "$TARGET" "mkdir -p '$REMOTE_DIR'"
scp "$BIN" "$TARGET:$REMOTE_DIR/nimbus-server"
scp "$REMOTE_CFG" "$TARGET:$REMOTE_DIR/server.json"

# 3. 启动；$! 必须由远程 bash 展开，因此此处转义
ssh "$TARGET" "cd '$REMOTE_DIR'; chmod +x nimbus-server; nohup ./nimbus-server -config server.json > server.log 2>&1 & echo \$! > server.pid; sleep 2; echo PID=\$(cat server.pid); cat server.log"
