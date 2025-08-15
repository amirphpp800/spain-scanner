#!/bin/bash
clear
echo "======================================"
echo "   IP Scanner for Termux"
echo "======================================"
echo ""

# Install required packages
pkg update -y
pkg install -y python curl git

# Download CIDR files (Replace with your own GitHub raw URLs)
curl -o ipv4.txt https://raw.githubusercontent.com/YourUserName/ip-scanner/main/ipv4.txt
curl -o ipv6.txt https://raw.githubusercontent.com/YourUserName/ip-scanner/main/ipv6.txt

# Create Python script
cat << 'EOF' > ip_scanner.py
import random
import ipaddress
import subprocess

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
                print(f"[✅ LIVE] {ip}")
            else:
                print(f"[❌ DEAD] {ip}")
        else:
            live_ips.append(ip)
            print(f"[🎯 GEN] {ip}")
    return live_ips

if __name__ == "__main__":
    print("1️⃣ IPv4 Ping Test")
    print("2️⃣ IPv6 Ping Test")
    print("3️⃣ IPv6 Without Ping")
    choice = input("Select mode: ").strip()

    if choice == "1":
        limit = int(input("Number of live IPv4 addresses needed: "))
        result = scan_ips("ipv4.txt", limit, ping_mode=True)
        print("\n[Live IPv4 Results]")
        print("\n".join(result))

    elif choice == "2":
        limit = int(input("Number of live IPv6 addresses needed: "))
        result = scan_ips("ipv6.txt", limit, ping_mode=True)
        print("\n[Live IPv6 Results]")
        print("\n".join(result))

    elif choice == "3":
        limit = int(input("Number of generated IPv6 addresses: "))
        result = scan_ips("ipv6.txt", limit, ping_mode=False)
        print("\n[Generated IPv6 Addresses]")
        print("\n".join(result))
EOF

# Run Python script
python ip_scanner.py
