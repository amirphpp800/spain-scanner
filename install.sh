#!/usr/bin/env bash

# Single entrypoint script to fetch Spain IPv4/IPv6 CIDR ranges and scan/generate IPs
# Requirements: bash, git, python3, grep, sed, sort. Optional: shuf, ping6 (or ping -6)

set -o pipefail

REPO_URL="https://github.com/amirphpp800/spain-scanner.git"
REPO_DIR="spain-scanner"
WORK_DIR="$(pwd)"
RANGES_V4_FILE="$WORK_DIR/ranges_ipv4.txt"
RANGES_V6_FILE="$WORK_DIR/ranges_ipv6.txt"
OUTPUT_V4_ALIVE="$WORK_DIR/alive_ipv4.txt"
OUTPUT_V6_ALIVE="$WORK_DIR/alive_ipv6.txt"
OUTPUT_V6_GEN="$WORK_DIR/generated_ipv6.txt"
NAMED_V4_IN_REPO="$REPO_DIR/ipv4.txt"
NAMED_V6_IN_REPO="$REPO_DIR/ipv6.txt"
NAMED_V4_IN_WORKDIR="$WORK_DIR/ipv4.txt"
NAMED_V6_IN_WORKDIR="$WORK_DIR/ipv6.txt"

# --- Styling / Colors ---
init_colors() {
  if [ -t 1 ] && [ -z "$NO_COLOR" ]; then
    RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
    RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; MAGENTA="\033[35m"; CYAN="\033[36m"; GRAY="\033[90m"
  else
    RESET=""; BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; GRAY=""
  fi
}

print_banner() {
  printf '%b' "${BOLD}${MAGENTA}┌─────────────────────────────────────────────────────┐${RESET}\n"
  printf '%b' "${BOLD}${MAGENTA}│${RESET}  ${BOLD}${CYAN}Spain IP Scanner${RESET}  ${GRAY}• IPv4/IPv6 CIDR Picker${RESET}  ${BOLD}${MAGENTA}│${RESET}\n"
  printf '%b' "${BOLD}${MAGENTA}└─────────────────────────────────────────────────────┘${RESET}\n"
}

print_panel() {
  # print_panel "Title" "multi\nline\nbody"
  local title="$1"; shift
  local body="$*"
  local width=${COLUMNS:-70}
  [ "$width" -lt 40 ] && width=70
  local inner=$((width-2))
  printf '%b' "${BOLD}${MAGENTA}┌"; for _ in $(seq 1 "$inner"); do printf '─'; done; printf '%b' "┐${RESET}\n"
  printf '%b' "${BOLD}${MAGENTA}│${RESET} ${BOLD}${title}${RESET}"
  local title_len=${#title}
  local rest=$((inner-1-title_len))
  [ "$rest" -lt 0 ] && rest=0
  for _ in $(seq 1 "$rest"); do printf ' '; done
  printf '%b' "${BOLD}${MAGENTA}│${RESET}\n"
  # Expand escapes in body (\n and color codes)
  local __save_ifs="$IFS"; IFS=$'\n'
  local body_expanded
  body_expanded=$(printf '%b' "$body")
  for line in $body_expanded; do
    printf '%b' "${BOLD}${MAGENTA}│${RESET} "
    printf '%b' "$line"
    local pad=$((inner-1-${#line}))
    [ "$pad" -lt 0 ] && pad=0
    for _ in $(seq 1 "$pad"); do printf ' '; done
    printf '%b' "${BOLD}${MAGENTA}│${RESET}\n"
  done
  IFS="$__save_ifs"
  printf '%b' "${BOLD}${MAGENTA}└"; for _ in $(seq 1 "$inner"); do printf '─'; done; printf '%b' "┘${RESET}\n"
}

print_err() { printf '%b' "${BOLD}${RED}[✖]${RESET} "; printf '%b\n' "$*" 1>&2; }
print_info() { printf '%b' "${BOLD}${CYAN}[i]${RESET} "; printf '%b\n' "$*"; }
print_ok() { printf '%b' "${BOLD}${GREEN}[✔]${RESET} "; printf '%b\n' "$*"; }

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    print_err "Missing required command: $1"
    exit 1
  fi
}

detect_ping_support() {
  # Detect environment to choose correct flags
  local uname_s="$(uname -s 2>/dev/null || echo unknown)"
  case "$uname_s" in
    MINGW*|MSYS*|CYGWIN*)
      # Windows ping (via Git-Bash) uses -n and -w (milliseconds)
      PING_COUNT_FLAG="-n"
      PING_WAIT_FLAG="-w"
      ;;
    *)
      # Assume GNU/BSD ping with -c and -W (seconds)
      PING_COUNT_FLAG="-c"
      PING_WAIT_FLAG="-W"
      ;;
  esac

  if command -v ping6 >/dev/null 2>&1; then
    PING6_BIN="ping6"
  else
    PING6_BIN="ping"
  fi
}

clone_or_update_repo() {
  if [ -d "$REPO_DIR/.git" ]; then
    print_info "Updating existing repo ${BOLD}$REPO_DIR${RESET} ..."
    git -C "$REPO_DIR" pull --ff-only || print_err "git pull failed; continuing with existing copy"
  else
    print_info "Cloning repository ${BOLD}$REPO_URL${RESET} ..."
    git clone --depth 1 "$REPO_URL" "$REPO_DIR" || {
      print_err "Failed to clone repository: $REPO_URL"
      exit 1
    }
  fi
}

extract_ranges() {
  local kind="$1" # v4 or v6
  local out_file="$2"
  local pattern
  if [ "$kind" = "v4" ]; then
    pattern='\b([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b'
  else
    # IPv6 CIDR pattern (coarse): sequences of hex groups and ':' ending with /prefix
    pattern='\b([0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}/[0-9]{1,3}\b'
  fi

  print_info "Scanning repo for ${kind} CIDR ranges ..."
  grep -RhoE "$pattern" "$REPO_DIR" 2>/dev/null | \
    sed 's/\r$//' | \
    sed 's/^[ \t]*//;s/[ \t]*$//' | \
    grep -vE '^#' | \
    sort -u > "$out_file"

  if [ ! -s "$out_file" ]; then
    print_err "No ${kind} CIDR ranges found in repository."
    exit 1
  fi

  local count
  count=$(wc -l < "$out_file" | tr -d ' ')
  print_ok "Found ${BOLD}$count${RESET} ${kind} ranges → ${BOLD}$out_file${RESET}"
}

normalize_ranges_file() {
  # usage: normalize_ranges_file input output
  local input="$1"; local output="$2"
  grep -E -v '^[ \t]*#' "$input" 2>/dev/null | \
    sed 's/\r$//' | \
    sed 's/^[ \t]*//;s/[ \t]*$//' | \
    awk 'NF>0' | \
    sort -u > "$output"
}

resolve_named_ranges_or_fallback() {
  local used_named=false
  if [ -f "$NAMED_V4_IN_REPO" ] && [ -f "$NAMED_V6_IN_REPO" ]; then
    print_info "Using named range files from repo: ${BOLD}ipv4.txt${RESET}, ${BOLD}ipv6.txt${RESET}"
    normalize_ranges_file "$NAMED_V4_IN_REPO" "$RANGES_V4_FILE"
    normalize_ranges_file "$NAMED_V6_IN_REPO" "$RANGES_V6_FILE"
    used_named=true
  elif [ -f "$NAMED_V4_IN_WORKDIR" ] && [ -f "$NAMED_V6_IN_WORKDIR" ]; then
    print_info "Using named range files from workdir: ${BOLD}ipv4.txt${RESET}, ${BOLD}ipv6.txt${RESET}"
    normalize_ranges_file "$NAMED_V4_IN_WORKDIR" "$RANGES_V4_FILE"
    normalize_ranges_file "$NAMED_V6_IN_WORKDIR" "$RANGES_V6_FILE"
    used_named=true
  fi

  if [ "$used_named" = false ]; then
    print_info "Named range files not found, scanning repository for CIDRs ..."
    extract_ranges v4 "$RANGES_V4_FILE"
    extract_ranges v6 "$RANGES_V6_FILE"
  else
    # Quick counts for info
    local c4 c6
    c4=$(wc -l < "$RANGES_V4_FILE" | tr -d ' ')
    c6=$(wc -l < "$RANGES_V6_FILE" | tr -d ' ')
    print_ok "Found ${BOLD}$c4${RESET} v4 ranges and ${BOLD}$c6${RESET} v6 ranges from named files"
  fi
}

# Pick one random line from a file, portable across environments
pick_one_random_line() {
  local file="$1"
  if command -v shuf >/dev/null 2>&1; then
    shuf -n 1 "$file"
  else
    python3 - "$file" <<'PY'
import os, random, sys
path = sys.argv[1]
with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    lines = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]
if not lines:
    sys.exit(1)
print(random.choice(lines))
PY
  fi
}

# Generate a random IP address within the given CIDR (IPv4 or IPv6)
random_ip_from_cidr() {
  local cidr="$1"
  python3 - "$cidr" <<'PY'
import ipaddress, os, random, sys
cidr = sys.argv[1].strip()
net = ipaddress.ip_network(cidr, strict=False)
# For huge subnets, sample uniformly by picking a random host index
size = net.num_addresses
# Avoid network/broadcast specifics handled by ipaddress for v4 automatically via hosts();
# But to keep speed, pick an index and ensure it's not network/broadcast where applicable.
for _ in range(32):
    idx = random.randrange(0, size)
    ip = net[idx]
    # Skip network/broadcast for IPv4 if present
    if isinstance(ip, ipaddress.IPv4Address) and (ip == net.network_address or ip == getattr(net, 'broadcast_address', ipaddress.IPv4Address('0.0.0.0'))):
        continue
    print(str(ip))
    sys.exit(0)
# Fallback: first usable host
try:
    print(str(next(net.hosts())))
except StopIteration:
    print(str(net.network_address))
PY
}

should_stick_to_range() {
  # 50% probability
  python3 - <<'PY'
import random
exit(0 if random.random() < 0.5 else 1)
PY
}

ping_ip() {
  local ip="$1"
  local fam="$2" # 4 or 6
  local timeout_s=1
  local timeout_ms=1000
  local count=3
  if [ "$fam" = "4" ]; then
    if [ "$PING_WAIT_FLAG" = "-w" ]; then
      ping $PING_COUNT_FLAG "$count" $PING_WAIT_FLAG "$timeout_ms" "$ip" >/dev/null 2>&1
    else
      ping $PING_COUNT_FLAG "$count" $PING_WAIT_FLAG "$timeout_s" "$ip" >/dev/null 2>&1
    fi
  else
    if [ "$PING6_BIN" = "ping6" ]; then
      if [ "$PING_WAIT_FLAG" = "-w" ]; then
        "$PING6_BIN" $PING_COUNT_FLAG "$count" $PING_WAIT_FLAG "$timeout_ms" "$ip" >/dev/null 2>&1
      else
        "$PING6_BIN" $PING_COUNT_FLAG "$count" $PING_WAIT_FLAG "$timeout_s" "$ip" >/dev/null 2>&1
      fi
    else
      if [ "$PING_WAIT_FLAG" = "-w" ]; then
        "$PING6_BIN" -6 $PING_COUNT_FLAG "$count" $PING_WAIT_FLAG "$timeout_ms" "$ip" >/dev/null 2>&1
      else
        "$PING6_BIN" -6 $PING_COUNT_FLAG "$count" $PING_WAIT_FLAG "$timeout_s" "$ip" >/dev/null 2>&1
      fi
    fi
  fi
}

scan_ipv4_with_ping() {
  local target_alive="$1"
  local alive_found=0
  local last_good_range=""
  : > "$OUTPUT_V4_ALIVE"
  print_info "Starting ${BOLD}IPv4${RESET} scan to find ${BOLD}$target_alive${RESET} alive IPs ${GRAY}(3 pings)${RESET} ..."
  while [ "$alive_found" -lt "$target_alive" ]; do
    local use_range
    if [ -n "$last_good_range" ] && should_stick_to_range; then
      use_range="$last_good_range"
    else
      use_range="$(pick_one_random_line "$RANGES_V4_FILE")"
    fi
    # Try a few random IPs from this range
    for _ in 1 2 3 4 5; do
      local candidate
      candidate="$(random_ip_from_cidr "$use_range")"
      if ping_ip "$candidate" 4; then
        printf '%b\n' "${GREEN}${candidate}${RESET}"
        echo "$candidate" >> "$OUTPUT_V4_ALIVE"
        last_good_range="$use_range"
        alive_found=$((alive_found + 1))
        break
      fi
    done
  done
  print_ok "Saved alive IPv4 addresses to: ${BOLD}$OUTPUT_V4_ALIVE${RESET}"
}

scan_ipv6_with_ping() {
  local target_alive="$1"
  local alive_found=0
  local last_good_range=""
  : > "$OUTPUT_V6_ALIVE"
  print_info "Starting ${BOLD}IPv6${RESET} scan to find ${BOLD}$target_alive${RESET} alive IPs ${GRAY}(3 pings)${RESET} ..."
  while [ "$alive_found" -lt "$target_alive" ]; do
    local use_range
    if [ -n "$last_good_range" ] && should_stick_to_range; then
      use_range="$last_good_range"
    else
      use_range="$(pick_one_random_line "$RANGES_V6_FILE")"
    fi
    for _ in 1 2 3 4 5; do
      local candidate
      candidate="$(random_ip_from_cidr "$use_range")"
      if ping_ip "$candidate" 6; then
        printf '%b\n' "${GREEN}${candidate}${RESET}"
        echo "$candidate" >> "$OUTPUT_V6_ALIVE"
        last_good_range="$use_range"
        alive_found=$((alive_found + 1))
        break
      fi
    done
  done
  print_ok "Saved alive IPv6 addresses to: ${BOLD}$OUTPUT_V6_ALIVE${RESET}"
}

generate_ipv6_without_ping() {
  local count="$1"
  : > "$OUTPUT_V6_GEN"
  print_info "Generating ${BOLD}$count${RESET} IPv6 addresses from random Spain ranges ${GRAY}(no ping)${RESET} ..."
  for _ in $(seq 1 "$count"); do
    local range
    range="$(pick_one_random_line "$RANGES_V6_FILE")"
    local ip
    ip="$(random_ip_from_cidr "$range")"
    printf '%b\n' "${GREEN}${ip}${RESET}"
    echo "$ip" >> "$OUTPUT_V6_GEN"
  done
  print_ok "Saved generated IPv6 addresses to: ${BOLD}$OUTPUT_V6_GEN${RESET}"
}

main_menu() {
  print_banner
  print_panel "Select mode" "${YELLOW}1)${RESET} IPv4 with ping ${GRAY}(find N alive)${RESET}\n${YELLOW}2)${RESET} IPv6 with ping ${GRAY}(find N alive)${RESET}\n${YELLOW}3)${RESET} IPv6 without ping ${GRAY}(generate N addresses)${RESET}\n${YELLOW}q)${RESET} Quit"
  read -rp "Enter choice [1-3]: " choice
  # Normalize input (trim CR/LF and spaces for Git-Bash/Windows)
  choice=$(printf "%s" "$choice" | tr -d '\r' | sed 's/^[ \t]*//;s/[ \t]*$//')
  case "$choice" in
    1)
      read -rp "How many alive IPv4 addresses to find? N = " n
      n=$(printf "%s" "$n" | tr -d '\r' | sed 's/^[ \t]*//;s/[ \t]*$//')
      if ! [[ "$n" =~ ^[0-9]+$ ]] || [ "$n" -le 0 ]; then
        print_err "Invalid number."; exit 1
      fi
      scan_ipv4_with_ping "$n"
      ;;
    2)
      read -rp "How many alive IPv6 addresses to find? N = " n
      n=$(printf "%s" "$n" | tr -d '\r' | sed 's/^[ \t]*//;s/[ \t]*$//')
      if ! [[ "$n" =~ ^[0-9]+$ ]] || [ "$n" -le 0 ]; then
        print_err "Invalid number."; exit 1
      fi
      scan_ipv6_with_ping "$n"
      ;;
    3)
      read -rp "How many IPv6 addresses to generate? N = " n
      n=$(printf "%s" "$n" | tr -d '\r' | sed 's/^[ \t]*//;s/[ \t]*$//')
      if ! [[ "$n" =~ ^[0-9]+$ ]] || [ "$n" -le 0 ]; then
        print_err "Invalid number."; exit 1
      fi
      generate_ipv6_without_ping "$n"
      ;;
    q|Q)
      print_info "Bye!"
      exit 0
      ;;
    *)
      print_err "Invalid choice."; exit 1
      ;;
  esac
}

setup() {
  init_colors
  require_cmd git
  require_cmd grep
  require_cmd sed
  require_cmd sort
  require_cmd python3
  require_cmd ping
  detect_ping_support
  clone_or_update_repo
  resolve_named_ranges_or_fallback
  # Show quick summary
  local c4 c6
  c4=$(wc -l < "$RANGES_V4_FILE" | tr -d ' ')
  c6=$(wc -l < "$RANGES_V6_FILE" | tr -d ' ')
  print_panel "Ranges Loaded" "IPv4 ranges: ${BOLD}$c4${RESET} → $RANGES_V4_FILE\nIPv6 ranges: ${BOLD}$c6${RESET} → $RANGES_V6_FILE"
}

setup
main_menu


