#!/bin/bash
# Spain IP Scanner - Termux Optimized Version

# --- Fix CRLF if needed ---
if grep -q $'\r' "$0" 2>/dev/null; then
    sed -i 's/\r$//' "$0" 2>/dev/null || true
    if [ -z "${RELOADED_AFTER_CRLF_FIX}" ]; then
        export RELOADED_AFTER_CRLF_FIX=1
        exec bash "$0" "$@"
    fi
fi

# --- UI Header ---
printf "\033c"
echo "======================================"
echo "   Spain IP Scanner - Termux (Optimized)"
echo "======================================"
echo ""

# --- Script Path ---
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# --- Safe Download Function ---
download_file() {
    local url="$1"
    local file="$2"
    echo "[*] Downloading $file..."
    if curl -sL --fail "$url" -o "$file"; then
        if [ -s "$file" ]; then
            echo "[✓] $file downloaded successfully"
        else
            echo "[ERROR] $file is empty after download"
            rm -f "$file"
            exit 1
        fi
    else
        echo "[ERROR] Failed to download $file"
        exit 1
    fi
}

# --- Check & Download CIDR Files ---
echo "[*] Checking CIDR files..."
[ ! -f "${SCRIPT_DIR}/ipv4.txt" ] && download_file "https://raw.githubusercontent.com/amirphpp800/spain-scanner/main/ipv4.txt" "${SCRIPT_DIR}/ipv4.txt"
[ ! -f "${SCRIPT_DIR}/ipv6.txt" ] && download_file "https://raw.githubusercontent.com/amirphpp800/spain-scanner/main/ipv6.txt" "${SCRIPT_DIR}/ipv6.txt"

# --- Check Python Dependency ---
echo "[*] Checking Python dependencies..."
pip show tabulate > /dev/null 2>&1 || pip install tabulate

# --- Create / Update Python Scanner ---
echo "[*] Creating Python scanner..."
cat > "${SCRIPT_DIR}/ip_scanner.py" << 'EOF'
import random
import ipaddress
import subprocess
import os
import threading
import time
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

class OptimizedScanner:
    def __init__(self, max_workers=40, ping_timeout=1):
        self.max_workers = max_workers
        self.ping_timeout = ping_timeout
        self.live_ips = []
        self.results = []
        self.scanned_count = 0
        self.lock = threading.Lock()
        self.good_cidrs = {}
        self.start_time = time.time()
        self.ping_cmd_ipv6 = self.detect_ping_ipv6()

    def detect_ping_ipv6(self):
        if shutil.which("ping6"):
            return "ping6"
        return "ping"

    def load_cidrs(self, filename):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(script_dir, filename)
        try:
            with open(filepath, "r") as f:
                cidrs = []
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            ipaddress.ip_network(line, strict=False)
                            cidrs.append(line)
                        except ValueError:
                            print(f"{YELLOW}[WARN]{RESET} Invalid CIDR on line {line_num}: {line}")
            if not cidrs:
                print(f"{RED}[ERROR]{RESET} No valid CIDR ranges in {filename}")
                exit(1)
            return cidrs
        except FileNotFoundError:
            print(f"{RED}[ERROR]{RESET} File {filename} not found!")
            exit(1)

    def generate_random_ip_fast(self, cidr):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            num_hosts = net.num_addresses - (2 if net.version == 4 else 0)
            if num_hosts <= 0:
                return str(net.network_address)
            rand_offset = random.randrange(1, num_hosts)
            return str(net.network_address + rand_offset)
        except:
            return None

    def ping_ip_fast(self, ip):
        try:
            is_ipv6 = ":" in ip
            cmd = []
            if is_ipv6:
                if self.ping_cmd_ipv6 == "ping6":
                    cmd = ["ping6", "-c", "1", "-W", str(self.ping_timeout), "-q", "-n", ip]
                else:
                    cmd = ["ping", "-6", "-c", "1", "-W", str(self.ping_timeout), "-q", "-n", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(self.ping_timeout), "-q", "-n", ip]

            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=self.ping_timeout + 0.5)
            return result.returncode == 0
        except:
            return False

    def update_cidr_stats(self, cidr, success):
        if cidr not in self.good_cidrs:
            self.good_cidrs[cidr] = {'hits': 0, 'total': 0}
        self.good_cidrs[cidr]['total'] += 1
        if success:
            self.good_cidrs[cidr]['hits'] += 1

    def smart_cidr_selection(self, cidrs):
        if not self.good_cidrs:
            return random.choice(cidrs)
        if random.random() < 0.7:
            successful_cidrs = [c for c, s in self.good_cidrs.items() if s['hits'] > 0 and s['total'] > 2]
            if successful_cidrs:
                weights = [self.good_cidrs[c]['hits'] / self.good_cidrs[c]['total'] for c in successful_cidrs]
                return random.choices(successful_cidrs, weights=weights)[0]
        return random.choice(cidrs)

    def scan_worker(self, ip_cidr_pairs, ping_mode, target_limit):
        for ip, cidr in ip_cidr_pairs:
            with self.lock:
                if ping_mode and len(self.live_ips) >= target_limit:
                    break
                if not ping_mode and self.scanned_count >= target_limit:
                    break

            success = False
            if ping_mode:
                success = self.ping_ip_fast(ip)
                if success:
                    with self.lock:
                        if len(self.live_ips) < target_limit:
                            self.live_ips.append(ip)
                            status = f"{GREEN}LIVE{RESET}"
                        else:
                            continue
                else:
                    status = f"{RED}DEAD{RESET}"
            else:
                with self.lock:
                    if self.scanned_count < target_limit:
                        self.live_ips.append(ip)
                        success = True
                        status = f"{BLUE}GENERATED{RESET}"
                    else:
                        continue

            with self.lock:
                self.scanned_count += 1
                self.results.append([ip, cidr, status])
                self.update_cidr_stats(cidr, success)

    def display_progress(self, target_limit, ping_mode):
        os.system("clear")
        current = len(self.live_ips) if ping_mode else self.scanned_count
        elapsed = time.time() - self.start_time
        rate = self.scanned_count / max(elapsed, 1)
        success_rate = (len(self.live_ips) / max(self.scanned_count, 1)) * 100 if ping_mode else 100
        print(f"{MAGENTA}╔══════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{MAGENTA}║                    SPAIN IP SCANNER STATUS                   ║{RESET}")
        print(f"{MAGENTA}╠══════════════════════════════════════════════════════════════╣{RESET}")
        print(f"{MAGENTA}║{RESET} Progress: {YELLOW}{current:>3}/{target_limit:<3}{RESET} {'Live IPs' if ping_mode else 'Generated':<12} {MAGENTA}║{RESET}")
        print(f"{MAGENTA}║{RESET} Scanned:  {CYAN}{self.scanned_count:>7}{RESET} total IPs                     {MAGENTA}║{RESET}")
        print(f"{MAGENTA}║{RESET} Rate:     {BLUE}{rate:>7.1f}{RESET} IPs/sec                       {MAGENTA}║{RESET}")
        print(f"{MAGENTA}║{RESET} Success:  {GREEN}{success_rate:>6.1f}%{RESET}                              {MAGENTA}║{RESET}")
        print(f"{MAGENTA}║{RESET} Time:     {YELLOW}{elapsed:>7.1f}{RESET} seconds                       {MAGENTA}║{RESET}")
        print(f"{MAGENTA}╚══════════════════════════════════════════════════════════════╝{RESET}")
        print()
        display_results = self.results[-15:] if len(self.results) > 15 else self.results
        if display_results:
            print(tabulate(display_results, headers=[f"{BLUE}IP Address{RESET}", f"{BLUE}CIDR Range{RESET}", f"{BLUE}Status{RESET}"], tablefmt="fancy_grid"))

    def scan_ips_optimized(self, filename, limit, ping_mode=True):
        cidrs = self.load_cidrs(filename)
        batch_multiplier = 3 if ping_mode else 1
        total_ips_needed = limit * batch_multiplier
        ip_batches = []
        batch_size = min(200, total_ips_needed // self.max_workers + 1)
        for batch_num in range(0, total_ips_needed, batch_size):
            batch = []
            for _ in range(min(batch_size, total_ips_needed - batch_num)):
                cidr = self.smart_cidr_selection(cidrs)
                ip = self.generate_random_ip_fast(cidr)
                if ip:
                    batch.append((ip, cidr))
            if batch:
                ip_batches.append(batch)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.scan_worker, batch, ping_mode, limit) for batch in ip_batches]
            last_update = 0
            while any(not f.done() for f in futures):
                current = len(self.live_ips) if ping_mode else self.scanned_count
                if time.time() - last_update > 2 or current >= limit:
                    self.display_progress(limit, ping_mode)
                    last_update = time.time()
                    if current >= limit:
                        for f in futures:
                            f.cancel()
                        break
                time.sleep(0.5)
            for future in as_completed(futures, timeout=1):
                try:
                    future.result()
                except:
                    pass
        self.display_progress(limit, ping_mode)
        return self.live_ips

def main():
    print(f"{GREEN}🚀 1️⃣ IPv4 Fast Ping Scan{RESET}")
    print(f"{GREEN}🚀 2️⃣ IPv6 Fast Ping Scan{RESET}")
    print(f"{GREEN}⚡ 3️⃣ IPv6 Ultra-Fast Generation{RESET}")
    choice = input(f"\n{YELLOW}Select mode (1-3): {RESET}").strip()
    if choice == "1":
        limit = int(input(f"{YELLOW}Number of live IPv4 addresses: {RESET}"))
        OptimizedScanner(max_workers=40, ping_timeout=1).scan_ips_optimized("ipv4.txt", limit, True)
    elif choice == "2":
        limit = int(input(f"{YELLOW}Number of live IPv6 addresses: {RESET}"))
        OptimizedScanner(max_workers=35, ping_timeout=1).scan_ips_optimized("ipv6.txt", limit, True)
    elif choice == "3":
        limit = int(input(f"{YELLOW}Number of IPv6 addresses to generate: {RESET}"))
        OptimizedScanner(max_workers=80, ping_timeout=1).scan_ips_optimized("ipv6.txt", limit, False)
    else:
        print(f"{RED}[ERROR]{RESET} Invalid choice!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[INFO]{RESET} Scan interrupted")
EOF

echo "[✓] Python scanner created/updated"

# --- Run Scanner ---
cd "${SCRIPT_DIR}"
python ip_scanner.py
