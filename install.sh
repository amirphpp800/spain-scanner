#!/bin/bash
clear
echo "======================================"
echo "   Spain IP Scanner - Termux"
echo "======================================"
echo ""

# Check & download CIDR files if missing
if [ ! -f "ipv4.txt" ]; then
    echo "[*] Downloading ipv4.txt..."
    curl -sO https://raw.githubusercontent.com/amirphpp800/spain-scanner/main/ipv4.txt
fi
if [ ! -f "ipv6.txt" ]; then
    echo "[*] Downloading ipv6.txt..."
    curl -sO https://raw.githubusercontent.com/amirphpp800/spain-scanner/main/ipv6.txt
fi

# Make sure Python module tabulate is installed
pip show tabulate > /dev/null 2>&1 || pip install tabulate

# Create Python scanner
cat << 'EOF' > /tmp/ip_scanner.py
import random
import ipaddress
import subprocess
import os
from tabulate import tabulate

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

def load_cidrs(filename):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

def generate_random_ip(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    return str(random.choice(list(net.hosts())))

def ping_ip(ip, count=3, timeout=1):
    is_ipv6 = ":" in ip
    cmd = ["ping6" if is_ipv6 else "ping", "-c", str(count), "-W", str(timeout), ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception:
        return False

def scan_ips(filename, limit, ping_mode=True):
    cidrs = load_cidrs(filename)
    live_ips = []
    results = []
    last_good_cidr = None

    while len(live_ips) < limit:
        if last_good_cidr and random.random() < 0.5:
            cidr = last_good_cidr
        else:
            cidr = random.choice(cidrs)

        ip = generate_random_ip(cidr)

        if ping_mode:
            if ping_ip(ip):
                live_ips.append(ip)
                last_good_cidr = cidr
                status = f"{GREEN}LIVE{RESET}"
            else:
                status = f"{RED}DEAD{RESET}"
        else:
            live_ips.append(ip)
            status = f"{BLUE}GENERATED{RESET}"

        results.append([ip, cidr, status])
        os.system("clear")
        print(f"{YELLOW}Scanning... Found {len(live_ips)}/{limit} IPs{RESET}")
        print(tabulate(results, headers=[f"{BLUE}IP Address{RESET}", f"{BLUE}CIDR{RESET}", f"{BLUE}Status{RESET}"], tablefmt="fancy_grid"))

if __name__ == "__main__":
    print(f"{GREEN}1️⃣ IPv4 Ping Test{RESET}")
    print(f"{GREEN}2️⃣ IPv6 Ping Test{RESET}")
    print(f"{GREEN}3️⃣ IPv6 Without Ping{RESET}")
    choice = input(f"{YELLOW}Select mode: {RESET}").strip()

    if choice == "1":
        limit = int(input(f"{YELLOW}Number of live IPv4 addresses: {RESET}"))
        scan_ips("ipv4.txt", limit, ping_mode=True)
    elif choice == "2":
        limit = int(input(f"{YELLOW}Number of live IPv6 addresses: {RESET}"))
        scan_ips("ipv6.txt", limit, ping_mode=True)
    elif choice == "3":
        limit = int(input(f"{YELLOW}Number of generated IPv6 addresses: {RESET}"))
        scan_ips("ipv6.txt", limit, ping_mode=False)
EOF

# Run scanner
python /tmp/ip_scanner.py
