#!/bin/bash
# Ensure we are running under Bash (not sh/dash)
if [ -z "$BASH_VERSION" ]; then
    exec bash "$0" "$@"
fi

# Normalize Windows CRLF line endings if present, then re-run once
SELF_PATH="${BASH_SOURCE[0]:-$0}"
if grep -q $'\r' "$SELF_PATH" 2>/dev/null; then
    sed -i 's/\r$//' "$SELF_PATH" 2>/dev/null || true
    if [ -z "${RELOADED_AFTER_CRLF_FIX}" ]; then
        export RELOADED_AFTER_CRLF_FIX=1
        exec bash "$SELF_PATH" "$@"
    fi
fi
clear
echo "======================================"
echo "   Spain IP Scanner - Termux (Optimized)"
echo "======================================"
echo ""

# Determine script directory for consistent file paths
SOURCE_PATH="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR="$(cd -- "$(dirname -- "$SOURCE_PATH")" >/dev/null 2>&1 && pwd)"

# Check & download CIDR files if missing with better error handling
echo "[*] Checking CIDR files..."
if [ ! -f "${SCRIPT_DIR}/ipv4.txt" ]; then
    echo "[*] Downloading ipv4.txt..."
    if ! curl -sL https://raw.githubusercontent.com/amirphpp800/spain-scanner/main/ipv4.txt -o "${SCRIPT_DIR}/ipv4.txt"; then
        echo "[ERROR] Failed to download ipv4.txt"
        exit 1
    fi
    echo "[✓] ipv4.txt downloaded successfully"
else
    echo "[✓] ipv4.txt already exists"
fi

if [ ! -f "${SCRIPT_DIR}/ipv6.txt" ]; then
    echo "[*] Downloading ipv6.txt..."
    if ! curl -sL https://raw.githubusercontent.com/amirphpp800/spain-scanner/main/ipv6.txt -o "${SCRIPT_DIR}/ipv6.txt"; then
        echo "[ERROR] Failed to download ipv6.txt"
        exit 1
    fi
    echo "[✓] ipv6.txt downloaded successfully"
else
    echo "[✓] ipv6.txt already exists"
fi

# Install dependencies efficiently
echo "[*] Checking Python dependencies..."
pip show tabulate > /dev/null 2>&1 || pip install tabulate

# Only create the Python script if it doesn't exist or if it's outdated
if [ ! -f "${SCRIPT_DIR}/ip_scanner.py" ] || [ "${BASH_SOURCE[0]}" -nt "${SCRIPT_DIR}/ip_scanner.py" ]; then
    echo "[*] Creating/updating Python scanner..."
    cat > "${SCRIPT_DIR}/ip_scanner.py" << 'EOF'
import random
import ipaddress
import subprocess
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate

# ANSI Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

class OptimizedScanner:
    def __init__(self, max_workers=40, ping_timeout=1, ping_count=1):
        self.max_workers = max_workers
        self.ping_timeout = ping_timeout
        self.ping_count = ping_count
        self.live_ips = []
        self.results = []
        self.scanned_count = 0
        self.lock = threading.Lock()
        self.good_cidrs = {}  # Track success rate per CIDR
        self.start_time = time.time()
        
    def load_cidrs(self, filename):
        """Load CIDR ranges with caching and validation"""
        # Get the script directory to find CIDR files
        script_dir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(script_dir, filename)
        
        try:
            with open(filepath, "r") as f:
                cidrs = []
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            # Validate CIDR
                            ipaddress.ip_network(line, strict=False)
                            cidrs.append(line)
                        except ValueError:
                            print(f"{YELLOW}[WARN]{RESET} Invalid CIDR on line {line_num}: {line}")
                            continue
            
            if not cidrs:
                print(f"{RED}[ERROR]{RESET} No valid CIDR ranges found in {filepath}")
                exit(1)
            
            print(f"{GREEN}[INFO]{RESET} Loaded {len(cidrs)} valid CIDR ranges from {filename}")
            return cidrs
        except FileNotFoundError:
            print(f"{RED}[ERROR]{RESET} File {filepath} not found!")
            print(f"{YELLOW}[INFO]{RESET} Make sure {filename} exists in the script directory")
            exit(1)

    def generate_random_ip_fast(self, cidr):
        """Optimized IP generation with caching"""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            if not hosts:  # Single host network
                return str(net.network_address)
            return str(random.choice(hosts))
        except Exception:
            return None

    def ping_ip_fast(self, ip):
        """Ultra-fast ping with minimal overhead"""
        try:
            is_ipv6 = ":" in ip
            cmd = ["ping6" if is_ipv6 else "ping", 
                   "-c", "1",  # Single ping for speed
                   "-W", str(self.ping_timeout),
                   "-q",  # Quiet mode
                   "-n",  # No DNS lookup
                   ip]
            
            result = subprocess.run(cmd, 
                                  stdout=subprocess.DEVNULL, 
                                  stderr=subprocess.DEVNULL,
                                  timeout=self.ping_timeout + 0.5)
            return result.returncode == 0
        except:
            return False

    def update_cidr_stats(self, cidr, success):
        """Update CIDR success statistics"""
        if cidr not in self.good_cidrs:
            self.good_cidrs[cidr] = {'hits': 0, 'total': 0}
        
        self.good_cidrs[cidr]['total'] += 1
        if success:
            self.good_cidrs[cidr]['hits'] += 1

    def smart_cidr_selection(self, cidrs):
        """Intelligent CIDR selection based on success rate"""
        if not self.good_cidrs:
            return random.choice(cidrs)
        
        # 70% chance to use successful CIDRs
        if random.random() < 0.7:
            successful_cidrs = [cidr for cidr, stats in self.good_cidrs.items() 
                              if stats['hits'] > 0 and stats['total'] > 2]
            if successful_cidrs:
                # Weight by success rate
                weights = [self.good_cidrs[cidr]['hits'] / self.good_cidrs[cidr]['total'] 
                          for cidr in successful_cidrs]
                return random.choices(successful_cidrs, weights=weights)[0]
        
        return random.choice(cidrs)

    def scan_worker(self, ip_cidr_pairs, ping_mode, target_limit):
        """Worker function for parallel scanning"""
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
        """Display current progress with statistics"""
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

        # Show recent results (last 15 for better visibility)
        display_results = self.results[-15:] if len(self.results) > 15 else self.results
        if display_results:
            print(tabulate(display_results, 
                          headers=[f"{BLUE}IP Address{RESET}", f"{BLUE}CIDR Range{RESET}", f"{BLUE}Status{RESET}"], 
                          tablefmt="fancy_grid"))

    def scan_ips_optimized(self, filename, limit, ping_mode=True):
        """Main optimized scanning function"""
        cidrs = self.load_cidrs(filename)
        
        print(f"{CYAN}[INFO]{RESET} Starting {'ping scan' if ping_mode else 'IP generation'} with {self.max_workers} workers")
        print(f"{CYAN}[INFO]{RESET} Target: {limit} {'live IPs' if ping_mode else 'IPs'}")
        
        # Pre-generate IP batches for efficiency
        batch_multiplier = 3 if ping_mode else 1  # Generate more IPs for ping mode
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

        print(f"{CYAN}[INFO]{RESET} Generated {len(ip_batches)} batches for processing")
        
        # Start parallel scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all batches
            futures = []
            for batch in ip_batches:
                future = executor.submit(self.scan_worker, batch, ping_mode, limit)
                futures.append(future)
            
            # Monitor progress
            last_update = 0
            while any(not f.done() for f in futures):
                current = len(self.live_ips) if ping_mode else self.scanned_count
                
                # Update display every 2 seconds or when target reached
                if time.time() - last_update > 2 or current >= limit:
                    self.display_progress(limit, ping_mode)
                    last_update = time.time()
                    
                    if current >= limit:
                        # Cancel remaining futures
                        for f in futures:
                            f.cancel()
                        break
                
                time.sleep(0.5)
            
            # Wait for completion
            for future in as_completed(futures, timeout=1):
                try:
                    future.result()
                except:
                    pass

        # Final display
        self.display_progress(limit, ping_mode)
        
        elapsed = time.time() - self.start_time
        final_count = len(self.live_ips)
        
        print(f"\n{GREEN}✓ SCAN COMPLETE!{RESET}")
        print(f"{GREEN}→{RESET} Found: {GREEN}{final_count}{RESET} {'live IPs' if ping_mode else 'IPs'}")
        print(f"{GREEN}→{RESET} Time: {YELLOW}{elapsed:.1f}{RESET} seconds")
        print(f"{GREEN}→{RESET} Rate: {BLUE}{self.scanned_count/elapsed:.1f}{RESET} scans/sec")
        
        if ping_mode and self.good_cidrs:
            best_cidr = max(self.good_cidrs.items(), 
                          key=lambda x: x[1]['hits'] / max(x[1]['total'], 1))
            success_rate = best_cidr[1]['hits'] / best_cidr[1]['total'] * 100
            print(f"{GREEN}→{RESET} Best CIDR: {CYAN}{best_cidr[0]}{RESET} ({success_rate:.1f}% success)")
        
        return self.live_ips

def main():
    print(f"{GREEN}🚀 1️⃣ IPv4 Fast Ping Scan{RESET}")
    print(f"{GREEN}🚀 2️⃣ IPv6 Fast Ping Scan{RESET}")
    print(f"{GREEN}⚡ 3️⃣ IPv6 Ultra-Fast Generation{RESET}")
    print(f"{YELLOW}⚙️  4️⃣ Custom Configuration{RESET}")
    
    choice = input(f"\n{YELLOW}Select mode (1-4): {RESET}").strip()
    
    if choice == "1":
        limit = int(input(f"{YELLOW}Number of live IPv4 addresses: {RESET}"))
        scanner = OptimizedScanner(max_workers=40, ping_timeout=1)
        scanner.scan_ips_optimized("ipv4.txt", limit, ping_mode=True)
        
    elif choice == "2":
        limit = int(input(f"{YELLOW}Number of live IPv6 addresses: {RESET}"))
        scanner = OptimizedScanner(max_workers=35, ping_timeout=1)  # IPv6 slightly slower
        scanner.scan_ips_optimized("ipv6.txt", limit, ping_mode=True)
        
    elif choice == "3":
        limit = int(input(f"{YELLOW}Number of IPv6 addresses to generate: {RESET}"))
        scanner = OptimizedScanner(max_workers=80, ping_timeout=1)  # More workers for generation
        scanner.scan_ips_optimized("ipv6.txt", limit, ping_mode=False)
        
    elif choice == "4":
        limit = int(input(f"{YELLOW}Number of addresses needed: {RESET}"))
        workers = int(input(f"{YELLOW}Number of threads (20-100, default 40): {RESET}") or "40")
        workers = max(20, min(100, workers))  # Limit range
        timeout = float(input(f"{YELLOW}Ping timeout in seconds (0.5-3, default 1): {RESET}") or "1")
        timeout = max(0.5, min(3, timeout))  # Limit range
        
        file_type = input(f"{YELLOW}File type (ipv4/ipv6): {RESET}").strip().lower()
        if file_type not in ['ipv4', 'ipv6']:
            file_type = 'ipv4'
            
        ping_mode = input(f"{YELLOW}Enable ping test? (y/n, default y): {RESET}").strip().lower()
        ping_mode = ping_mode != 'n'
        
        scanner = OptimizedScanner(max_workers=workers, ping_timeout=timeout)
        filename = f"{file_type}.txt"
        scanner.scan_ips_optimized(filename, limit, ping_mode=ping_mode)
    else:
        print(f"{RED}[ERROR]{RESET} Invalid choice! Please select 1-4.")
        return

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[INFO]{RESET} Scan interrupted by user")
    except Exception as e:
        print(f"\n{RED}[ERROR]{RESET} Unexpected error: {e}")
EOF

    echo "[✓] Python scanner created/updated"
else
    echo "[✓] Python scanner is up to date"
fi

# Run the optimized scanner from current directory
cd "${SCRIPT_DIR}"
python ip_scanner.py
