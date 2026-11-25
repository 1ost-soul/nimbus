#!/usr/bin/env bash
# 公开仓库脱敏检查；发现敏感字符串或禁止文件则退出 1。
# 本脚本与 WHITELIST.txt 自身包含检测词，按设计跳过。
set -uo pipefail
cd "$(dirname "$0")" || exit 2

PATTERNS=(
  '1ostsoul'
  'dpdns'
  '2400:8d60'
  'iHwCso'
  'gho_s0by'
  '59/hpbRZ'
  '34433'
  '31323'
  'tunnel-ca'
  'answer.md'
  'lineb'
  'LBP'
  'LINEB001'
  'InsecureSkipVerify: *true'
)

SKIP=('./check_public.sh' './WHITELIST.txt' './third_party/quic-go-bbr')

FOUND=0
for f in $(find . -type f | sort); do
  skip=0
  for s in "${SKIP[@]}"; do [ "$f" = "$s" ] && skip=1; done
  case "$f" in ./third_party/quic-go-bbr/*) skip=1 ;; esac
  [ "$skip" -eq 1 ] && continue
  # 二进制文件（含 release 压缩包）会出现随机的模式字节串，只检查文本文件。
  case "$f" in
    *.zip|*.exe|*.pem|*.pcap|*.png|*.jpg|*.gif) continue ;;
  esac
  for p in "${PATTERNS[@]}"; do
    if grep -Eqi -- "$p" "$f"; then
      echo "FAIL sensitive pattern '$p' in $f"
      FOUND=1
    fi
  done
done

for bad in $(find . -type f \( -name '*.log' -o -name '*.pem' -o -name '*.pid' -o -name '*.exe' -o -name '*.pcap' -o -name 'answer.md' \) | sort); do
  echo "FAIL forbidden file $bad"
  FOUND=1
done

if [ "$FOUND" -eq 0 ]; then
  echo "PASS: public package is sanitized"
else
  echo "FAILED: do not publish"
  exit 1
fi
