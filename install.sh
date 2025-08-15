#!/usr/bin/env bash

#═══════════════════════════════════════════════════════════════════════════════
#                          Spain IP Scanner v2.0
#                     Enhanced IPv4/IPv6 CIDR Scanner
#═══════════════════════════════════════════════════════════════════════════════
# Requirements: bash, git, python3, grep, sed, sort, ping
# Optional: shuf, ping6
#═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

#───────────────────────────────────────────────────────────────────────────────
# Configuration Variables
#───────────────────────────────────────────────────────────────────────────────
readonly SCRIPT_VERSION="2.0"
readonly REPO_URL="https://github.com/amirphpp800/spain-scanner.git"
readonly REPO_DIR="spain-scanner"
readonly WORK_DIR="$(pwd)"

# Output files
readonly RANGES_V4_FILE="$WORK_DIR/ranges_ipv4.txt"
readonly RANGES_V6_FILE="$WORK_DIR/ranges_ipv6.txt"
readonly OUTPUT_V4_ALIVE="$WORK_DIR/alive_ipv4.txt"
readonly OUTPUT_V6_ALIVE="$WORK_DIR/alive_ipv6.txt"
readonly OUTPUT_V6_GEN="$WORK_DIR/generated_ipv6.txt"

# Ping configuration
readonly PING_TIMEOUT_S=2
readonly PING_TIMEOUT_MS=2000
readonly PING_COUNT=3
readonly MAX_ATTEMPTS_PER_RANGE=8

#───────────────────────────────────────────────────────────────────────────────
# Color and Style Definitions
#───────────────────────────────────────────────────────────────────────────────
init_colors() {
    if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
        # Reset and modifiers
        readonly RESET="\033[0m"
        readonly BOLD="\033[1m"
        readonly DIM="\033[2m"
        readonly UNDERLINE="\033[4m"
        readonly BLINK="\033[5m"
        
        # Colors
        readonly BLACK="\033[30m"
        readonly RED="\033[31m"
        readonly GREEN="\033[32m"
        readonly YELLOW="\033[33m"
        readonly BLUE="\033[34m"
        readonly MAGENTA="\033[35m"
        readonly CYAN="\033[36m"
        readonly WHITE="\033[37m"
        readonly GRAY="\033[90m"
        
        # Bright colors
        readonly BRIGHT_RED="\033[91m"
        readonly BRIGHT_GREEN="\033[92m"
        readonly BRIGHT_YELLOW="\033[93m"
        readonly BRIGHT_BLUE="\033[94m"
        readonly BRIGHT_MAGENTA="\033[95m"
        readonly BRIGHT_CYAN="\033[96m"
        
        # Background colors
        readonly BG_RED="\033[41m"
        readonly BG_GREEN="\033[42m"
        readonly BG_YELLOW="\033[43m"
        readonly BG_BLUE="\033[44m"
        readonly BG_MAGENTA="\033[45m"
        readonly BG_CYAN="\033[46m"
    else
        readonly RESET="" BOLD="" DIM="" UNDERLINE="" BLINK=""
        readonly BLACK="" RED="" GREEN="" YELLOW="" BLUE="" MAGENTA="" CYAN="" WHITE="" GRAY=""
        readonly BRIGHT_RED="" BRIGHT_GREEN="" BRIGHT_YELLOW="" BRIGHT_BLUE="" BRIGHT_MAGENTA="" BRIGHT_CYAN=""
        readonly BG_RED="" BG_GREEN="" BG_YELLOW="" BG_BLUE="" BG_MAGENTA="" BG_CYAN=""
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# UI and Display Functions
#───────────────────────────────────────────────────────────────────────────────
print_banner() {
    clear
    printf "\n"
    printf "${BOLD}${BRIGHT_CYAN}╔═══════════════════════════════════════════════════════════════════╗${RESET}\n"
    printf "${BOLD}${BRIGHT_CYAN}║${RESET}                                                                   ${BOLD}${BRIGHT_CYAN}║${RESET}\n"
    printf "${BOLD}${BRIGHT_CYAN}║${RESET}    ${BOLD}${BRIGHT_MAGENTA}🇪🇸 SPAIN IP SCANNER ${BRIGHT_YELLOW}v${SCRIPT_VERSION}${RESET} ${BOLD}${BRIGHT_MAGENTA}🇪🇸${RESET}                        ${BOLD}${BRIGHT_CYAN}║${RESET}\n"
    printf "${BOLD}${BRIGHT_CYAN}║${RESET}                                                                   ${BOLD}${BRIGHT_CYAN}║${RESET}\n"
    printf "${BOLD}${BRIGHT_CYAN}║${RESET}     ${BRIGHT_BLUE}Advanced IPv4/IPv6 CIDR Range Scanner${RESET}               ${BOLD}${BRIGHT_CYAN}║${RESET}\n"
    printf "${BOLD}${BRIGHT_CYAN}║${RESET}     ${GRAY}Discover and analyze Spanish IP ranges${RESET}                   ${BOLD}${BRIGHT_CYAN}║${RESET}\n"
    printf "${BOLD}${BRIGHT_CYAN}║${RESET}                                                                   ${BOLD}${BRIGHT_CYAN}║${RESET}\n"
    printf "${BOLD}${BRIGHT_CYAN}╚═══════════════════════════════════════════════════════════════════╝${RESET}\n"
    printf "\n"
}

print_section_header() {
    local title="$1"
    printf "\n${BOLD}${BRIGHT_BLUE}┌─ ${title} ${RESET}${BOLD}${BRIGHT_BLUE}─────────────────────────────────────────────────────┐${RESET}\n"
}

print_section_footer() {
    printf "${BOLD}${BRIGHT_BLUE}└─────────────────────────────────────────────────────────────────┘${RESET}\n\n"
}

print_error() {
    printf "${BOLD}${BG_RED}${WHITE} ERROR ${RESET} ${BOLD}${BRIGHT_RED}%s${RESET}\n" "$*" >&2
}

print_warning() {
    printf "${BOLD}${BG_YELLOW}${BLACK} WARN ${RESET} ${BOLD}${BRIGHT_YELLOW}%s${RESET}\n" "$*"
}

print_info() {
    printf "${BOLD}${BG_BLUE}${WHITE} INFO ${RESET} ${BOLD}${BRIGHT_BLUE}%s${RESET}\n" "$*"
}

print_success() {
    printf "${BOLD}${BG_GREEN}${WHITE} OK ${RESET} ${BOLD}${BRIGHT_GREEN}%s${RESET}\n" "$*"
}

print_progress() {
    printf "${BOLD}${CYAN}⚡${RESET} ${BOLD}%s${RESET}\n" "$*"
}

print_found_ip() {
    local ip="$1"
    local type="$2"
    if [[ "$type" == "v4" ]]; then
        printf "    ${BOLD}${BRIGHT_GREEN}✓${RESET} ${BRIGHT_GREEN}%s${RESET} ${GRAY}(IPv4)${RESET}\n" "$ip"
    else
        printf "    ${BOLD}${BRIGHT_GREEN}✓${RESET} ${BRIGHT_GREEN}%s${RESET} ${GRAY}(IPv6)${RESET}\n" "$ip"
    fi
}

print_generated_ip() {
    local ip="$1"
    printf "    ${BOLD}${BRIGHT_CYAN}→${RESET} ${BRIGHT_CYAN}%s${RESET} ${GRAY}(generated)${RESET}\n" "$ip"
}

#───────────────────────────────────────────────────────────────────────────────
# System Requirements and Setup
#───────────────────────────────────────────────────────────────────────────────
check_requirements() {
    print_section_header "System Requirements Check"
    
    local missing_deps=()
    local deps=("git" "grep" "sed" "sort" "python3" "ping")
    
    for dep in "${deps[@]}"; do
        if command -v "$dep" >/dev/null 2>&1; then
            printf "    ${BOLD}${GREEN}✓${RESET} ${dep} ${GRAY}($(command -v "$dep"))${RESET}\n"
        else
            printf "    ${BOLD}${RED}✗${RESET} ${dep} ${BRIGHT_RED}(missing)${RESET}\n"
            missing_deps+=("$dep")
        fi
    done
    
    # Check optional dependencies
    if command -v shuf >/dev/null 2>&1; then
        printf "    ${BOLD}${CYAN}+${RESET} shuf ${GRAY}(optional - available)${RESET}\n"
    else
        printf "    ${BOLD}${YELLOW}!${RESET} shuf ${GRAY}(optional - missing, using Python fallback)${RESET}\n"
    fi
    
    if command -v ping6 >/dev/null 2>&1; then
        printf "    ${BOLD}${CYAN}+${RESET} ping6 ${GRAY}(optional - available)${RESET}\n"
    else
        printf "    ${BOLD}${YELLOW}!${RESET} ping6 ${GRAY}(optional - missing, using ping -6)${RESET}\n"
    fi
    
    print_section_footer
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        print_info "Please install missing dependencies and try again."
        exit 1
    fi
    
    print_success "All required dependencies are available!"
}

detect_ping_configuration() {
    local uname_s
    uname_s="$(uname -s 2>/dev/null || echo unknown)"
    
    case "$uname_s" in
        MINGW*|MSYS*|CYGWIN*)
            # Windows ping via Git-Bash
            PING_COUNT_FLAG="-n"
            PING_WAIT_FLAG="-w"
            PING_TIMEOUT="$PING_TIMEOUT_MS"
            ;;
        *)
            # Unix-like systems
            PING_COUNT_FLAG="-c"
            PING_WAIT_FLAG="-W"
            PING_TIMEOUT="$PING_TIMEOUT_S"
            ;;
    esac
    
    # Determine IPv6 ping command
    if command -v ping6 >/dev/null 2>&1; then
        PING6_CMD="ping6"
        PING6_IPV6_FLAG=""
    else
        PING6_CMD="ping"
        PING6_IPV6_FLAG="-6"
    fi
    
    print_info "Ping configuration: ${PING_COUNT_FLAG} ${PING_COUNT} ${PING_WAIT_FLAG} ${PING_TIMEOUT}"
}

#───────────────────────────────────────────────────────────────────────────────
# Repository Management
#───────────────────────────────────────────────────────────────────────────────
manage_repository() {
    print_section_header "Repository Management"
    
    if [[ -d "$REPO_DIR/.git" ]]; then
        print_progress "Updating existing repository..."
        if git -C "$REPO_DIR" pull --ff-only >/dev/null 2>&1; then
            print_success "Repository updated successfully"
        else
            print_warning "Failed to update repository, using existing version"
        fi
    else
        print_progress "Cloning repository from ${BRIGHT_CYAN}${REPO_URL}${RESET}..."
        if git clone --depth 1 --quiet "$REPO_URL" "$REPO_DIR" 2>/dev/null; then
            print_success "Repository cloned successfully"
        else
            print_error "Failed to clone repository: $REPO_URL"
            exit 1
        fi
    fi
    
    print_section_footer
}

#───────────────────────────────────────────────────────────────────────────────
# CIDR Range Extraction
#───────────────────────────────────────────────────────────────────────────────
extract_ip_ranges() {
    print_section_header "CIDR Range Extraction"
    
    extract_ranges_by_type "v4" "$RANGES_V4_FILE"
    extract_ranges_by_type "v6" "$RANGES_V6_FILE"
    
    print_section_footer
}

extract_ranges_by_type() {
    local ip_type="$1"
    local output_file="$2"
    local pattern regex_name
    
    if [[ "$ip_type" == "v4" ]]; then
        pattern='\b([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b'
        regex_name="IPv4"
    else
        pattern='\b([0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}/[0-9]{1,3}\b'
        regex_name="IPv6"
    fi
    
    print_progress "Extracting ${regex_name} CIDR ranges..."
    
    if grep -RhoE "$pattern" "$REPO_DIR" 2>/dev/null | \
       sed 's/\r$//' | \
       sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
       grep -vE '^#' | \
       sort -u > "$output_file"; then
        
        if [[ -s "$output_file" ]]; then
            local count
            count=$(wc -l < "$output_file" | tr -d ' ')
            print_success "Found ${BOLD}${count}${RESET}${BOLD}${BRIGHT_GREEN} ${regex_name} ranges → ${output_file##*/}${RESET}"
        else
            print_error "No ${regex_name} CIDR ranges found in repository"
            exit 1
        fi
    else
        print_error "Failed to extract ${regex_name} ranges"
        exit 1
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# Utility Functions
#───────────────────────────────────────────────────────────────────────────────
pick_random_line() {
    local file="$1"
    
    if command -v shuf >/dev/null 2>&1; then
        shuf -n 1 "$file"
    else
        python3 - "$file" <<'EOF'
import random, sys
with open(sys.argv[1], 'r', encoding='utf-8', errors='ignore') as f:
    lines = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]
if lines:
    print(random.choice(lines))
else:
    sys.exit(1)
EOF
    fi
}

generate_random_ip_from_cidr() {
    local cidr="$1"
    python3 - "$cidr" <<'EOF'
import ipaddress, random, sys
try:
    cidr = sys.argv[1].strip()
    net = ipaddress.ip_network(cidr, strict=False)
    
    # Generate random IP within the network
    max_attempts = 50
    for _ in range(max_attempts):
        idx = random.randrange(0, net.num_addresses)
        ip = net[idx]
        
        # Skip network/broadcast addresses for IPv4
        if (isinstance(ip, ipaddress.IPv4Address) and 
            (ip == net.network_address or 
             (hasattr(net, 'broadcast_address') and ip == net.broadcast_address))):
            continue
            
        print(str(ip))
        sys.exit(0)
    
    # Fallback: use first host
    try:
        print(str(next(net.hosts())))
    except StopIteration:
        print(str(net.network_address))
        
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
EOF
}

should_stick_to_successful_range() {
    # 60% probability to stick with successful range
    python3 -c "import random; exit(0 if random.random() < 0.6 else 1)"
}

test_ip_connectivity() {
    local ip="$1"
    local ip_version="$2"
    
    if [[ "$ip_version" == "4" ]]; then
        ping $PING_COUNT_FLAG "$PING_COUNT" $PING_WAIT_FLAG "$PING_TIMEOUT" "$ip" >/dev/null 2>&1
    else
        if [[ -n "$PING6_IPV6_FLAG" ]]; then
            $PING6_CMD $PING6_IPV6_FLAG $PING_COUNT_FLAG "$PING_COUNT" $PING_WAIT_FLAG "$PING_TIMEOUT" "$ip" >/dev/null 2>&1
        else
            $PING6_CMD $PING_COUNT_FLAG "$PING_COUNT" $PING_WAIT_FLAG "$PING_TIMEOUT" "$ip" >/dev/null 2>&1
        fi
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# IP Scanning Functions
#───────────────────────────────────────────────────────────────────────────────
scan_for_alive_ipv4() {
    local target_count="$1"
    local found_count=0
    local successful_range=""
    
    print_section_header "IPv4 Connectivity Scan"
    print_info "Searching for ${BOLD}${target_count}${RESET}${BOLD}${BRIGHT_BLUE} alive IPv4 addresses${RESET}"
    printf "\n"
    
    > "$OUTPUT_V4_ALIVE"
    
    while [[ $found_count -lt $target_count ]]; do
        local current_range
        
        # Use successful range 60% of the time if available
        if [[ -n "$successful_range" ]] && should_stick_to_successful_range; then
            current_range="$successful_range"
        else
            current_range=$(pick_random_line "$RANGES_V4_FILE")
        fi
        
        # Try multiple IPs from the current range
        for attempt in $(seq 1 $MAX_ATTEMPTS_PER_RANGE); do
            [[ $found_count -ge $target_count ]] && break
            
            local test_ip
            test_ip=$(generate_random_ip_from_cidr "$current_range")
            
            if test_ip_connectivity "$test_ip" "4"; then
                print_found_ip "$test_ip" "v4"
                echo "$test_ip" >> "$OUTPUT_V4_ALIVE"
                successful_range="$current_range"
                ((found_count++))
                break
            fi
        done
        
        # Show progress every 10 attempts
        if (( (found_count % 5) == 0 )) && [[ $found_count -gt 0 ]]; then
            printf "    ${GRAY}Progress: ${found_count}/${target_count} found${RESET}\n"
        fi
    done
    
    printf "\n"
    print_success "IPv4 scan completed! Found ${BOLD}${found_count}${RESET}${BOLD}${BRIGHT_GREEN} alive addresses${RESET}"
    print_info "Results saved to: ${BOLD}${OUTPUT_V4_ALIVE##*/}${RESET}"
    print_section_footer
}

scan_for_alive_ipv6() {
    local target_count="$1"
    local found_count=0
    local successful_range=""
    
    print_section_header "IPv6 Connectivity Scan"
    print_info "Searching for ${BOLD}${target_count}${RESET}${BOLD}${BRIGHT_BLUE} alive IPv6 addresses${RESET}"
    printf "\n"
    
    > "$OUTPUT_V6_ALIVE"
    
    while [[ $found_count -lt $target_count ]]; do
        local current_range
        
        # Use successful range 60% of the time if available
        if [[ -n "$successful_range" ]] && should_stick_to_successful_range; then
            current_range="$successful_range"
        else
            current_range=$(pick_random_line "$RANGES_V6_FILE")
        fi
        
        # Try multiple IPs from the current range
        for attempt in $(seq 1 $MAX_ATTEMPTS_PER_RANGE); do
            [[ $found_count -ge $target_count ]] && break
            
            local test_ip
            test_ip=$(generate_random_ip_from_cidr "$current_range")
            
            if test_ip_connectivity "$test_ip" "6"; then
                print_found_ip "$test_ip" "v6"
                echo "$test_ip" >> "$OUTPUT_V6_ALIVE"
                successful_range="$current_range"
                ((found_count++))
                break
            fi
        done
        
        # Show progress every 5 successful finds
        if (( (found_count % 5) == 0 )) && [[ $found_count -gt 0 ]]; then
            printf "    ${GRAY}Progress: ${found_count}/${target_count} found${RESET}\n"
        fi
    done
    
    printf "\n"
    print_success "IPv6 scan completed! Found ${BOLD}${found_count}${RESET}${BOLD}${BRIGHT_GREEN} alive addresses${RESET}"
    print_info "Results saved to: ${BOLD}${OUTPUT_V6_ALIVE##*/}${RESET}"
    print_section_footer
}

generate_ipv6_addresses() {
    local count="$1"
    
    print_section_header "IPv6 Address Generation"
    print_info "Generating ${BOLD}${count}${RESET}${BOLD}${BRIGHT_CYAN} IPv6 addresses from Spanish ranges${RESET}"
    printf "\n"
    
    > "$OUTPUT_V6_GEN"
    
    for i in $(seq 1 "$count"); do
        local random_range
        random_range=$(pick_random_line "$RANGES_V6_FILE")
        
        local generated_ip
        generated_ip=$(generate_random_ip_from_cidr "$random_range")
        
        print_generated_ip "$generated_ip"
        echo "$generated_ip" >> "$OUTPUT_V6_GEN"
    done
    
    printf "\n"
    print_success "Generated ${BOLD}${count}${RESET}${BOLD}${BRIGHT_GREEN} IPv6 addresses${RESET}"
    print_info "Results saved to: ${BOLD}${OUTPUT_V6_GEN##*/}${RESET}"
    print_section_footer
}

#───────────────────────────────────────────────────────────────────────────────
# Interactive Menu System
#───────────────────────────────────────────────────────────────────────────────
display_main_menu() {
    printf "${BOLD}${BRIGHT_YELLOW}┌─ SELECT OPERATION MODE ────────────────────────────────────────────┐${RESET}\n"
    printf "${BOLD}${BRIGHT_YELLOW}│${RESET}                                                                    ${BOLD}${BRIGHT_YELLOW}│${RESET}\n"
    printf "${BOLD}${BRIGHT_YELLOW}│${RESET}  ${BOLD}${BRIGHT_GREEN}[1]${RESET} ${BOLD}IPv4 Alive Scan${RESET}     ${GRAY}Find N responsive IPv4 addresses${RESET}     ${BOLD}${BRIGHT_YELLOW}│${RESET}\n"
    printf "${BOLD}${BRIGHT_YELLOW}│${RESET}                                                                    ${BOLD}${BRIGHT_YELLOW}│${RESET}\n"
    printf "${BOLD}${BRIGHT_YELLOW}│${RESET}  ${BOLD}${BRIGHT_BLUE}[2]${RESET} ${BOLD}IPv6 Alive Scan${RESET}     ${GRAY}Find N responsive IPv6 addresses${RESET}     ${BOLD}${BRIGHT_YELLOW}│${RESET}\n"
    printf "${BOLD}${BRIGHT_YELLOW}│${RESET}                                                                    ${BOLD}${BRIGHT_YELLOW}│${RESET}\n"
    printf "${BOLD}${BRIGHT_YELLOW}│${RESET}  ${BOLD}${BRIGHT_CYAN}[3]${RESET} ${BOLD}IPv6 Generation${RESET}     ${GRAY}Generate N IPv6 addresses (no ping)${RESET}  ${BOLD}${BRIGHT_YELLOW}│${RESET}\n"
    printf "${BOLD}${BRIGHT_YELLOW}│${RESET}                                                                    ${BOLD}${BRIGHT_YELLOW}│${RESET}\n"
    printf "${BOLD}${BRIGHT_YELLOW}│${RESET}  ${BOLD}${BRIGHT_RED}[0]${RESET} ${BOLD}Exit${RESET}                                                        ${BOLD}${BRIGHT_YELLOW}│${RESET}\n"
    printf "${BOLD}${BRIGHT_YELLOW}│${RESET}                                                                    ${BOLD}${BRIGHT_YELLOW}│${RESET}\n"
    printf "${BOLD}${BRIGHT_YELLOW}└────────────────────────────────────────────────────────────────────┘${RESET}\n"
    printf "\n"
}

get_user_input() {
    local prompt="$1"
    local validation_regex="$2"
    local error_message="$3"
    local input
    
    while true; do
        printf "${BOLD}${BRIGHT_MAGENTA}%s${RESET} " "$prompt"
        read -r input
        
        if [[ "$input" =~ $validation_regex ]]; then
            echo "$input"
            return 0
        else
            print_error "$error_message"
            printf "\n"
        fi
    done
}

run_interactive_menu() {
    while true; do
        display_main_menu
        
        local choice
        choice=$(get_user_input "Enter your choice [0-3]:" "^[0-3]$" "Please enter a valid option (0-3)")
        
        case "$choice" in
            1)
                printf "\n"
                local ipv4_count
                ipv4_count=$(get_user_input "How many alive IPv4 addresses to find:" "^[1-9][0-9]*$" "Please enter a positive number")
                scan_for_alive_ipv4 "$ipv4_count"
                printf "${GRAY}Press Enter to continue...${RESET}"
                read -r
                print_banner
                ;;
            2)
                printf "\n"
                local ipv6_count
                ipv6_count=$(get_user_input "How many alive IPv6 addresses to find:" "^[1-9][0-9]*$" "Please enter a positive number")
                scan_for_alive_ipv6 "$ipv6_count"
                printf "${GRAY}Press Enter to continue...${RESET}"
                read -r
                print_banner
                ;;
            3)
                printf "\n"
                local gen_count
                gen_count=$(get_user_input "How many IPv6 addresses to generate:" "^[1-9][0-9]*$" "Please enter a positive number")
                generate_ipv6_addresses "$gen_count"
                printf "${GRAY}Press Enter to continue...${RESET}"
                read -r
                print_banner
                ;;
            0)
                printf "\n"
                print_success "Thank you for using Spain IP Scanner!"
                printf "${GRAY}Goodbye! 👋${RESET}\n\n"
                exit 0
                ;;
        esac
    done
}

#───────────────────────────────────────────────────────────────────────────────
# Signal Handlers and Cleanup
#───────────────────────────────────────────────────────────────────────────────
cleanup_on_exit() {
    printf "\n\n${YELLOW}Cleaning up...${RESET}\n"
    # Add any cleanup operations here if needed
    exit 0
}

trap cleanup_on_exit INT TERM

#───────────────────────────────────────────────────────────────────────────────
# Main Execution Flow
#───────────────────────────────────────────────────────────────────────────────
main() {
    init_colors
    print_banner
    
    check_requirements
    detect_ping_configuration
    manage_repository
    extract_ip_ranges
    
    print_success "Setup completed successfully! Ready to scan."
    printf "\n${GRAY}Press Enter to continue...${RESET}"
    read -r
    
    print_banner
    run_interactive_menu
}

# Execute main function
main "$@"
