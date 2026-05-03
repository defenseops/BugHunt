#!/usr/bin/env bash
# Verify all scanner tools are available in PATH
# Run inside container: bash check_tools.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

check() {
  local tool="$1"
  local cmd="${2:-$1}"
  if command -v "$cmd" &>/dev/null; then
    echo -e "${GREEN}  ✓${NC} $tool"
    ((PASS++))
  else
    echo -e "${RED}  ✗${NC} $tool"
    ((FAIL++))
  fi
}

warn() {
  local tool="$1"
  local path="$2"
  if [[ -f "$path" ]]; then
    echo -e "${GREEN}  ✓${NC} $tool (at $path)"
    ((PASS++))
  else
    echo -e "${YELLOW}  ?${NC} $tool (optional, not found at $path)"
    ((WARN++))
  fi
}

echo "=== Network ==="
check nmap
check masscan
check rustscan
check hping3
check netdiscover
check arp-scan
check tcpdump
check tshark

echo ""
echo "=== Port Scanners ==="
check naabu
check nmap

echo ""
echo "=== Web ==="
check nikto
check sqlmap
check gobuster
check ffuf
check feroxbuster
check dirsearch
check wafw00f
check whatweb
check httpx
check katana
check hakrawler
check dalfox
check nuclei
check gowitness
check webanalyze

echo ""
echo "=== SSL/TLS ==="
check sslyze
check sslscan

echo ""
echo "=== DNS / Recon ==="
check subfinder
check dnsx
check dnsrecon
check fierce
check assetfinder
check waybackurls
check gau
check theharvester
check recon-ng

echo ""
echo "=== Brute Force ==="
check hydra
check medusa
check ncrack
check kerbrute

echo ""
echo "=== SMB / AD ==="
check enum4linux
check smbmap
check nbtscan

echo ""
echo "=== Credentials ==="
check john
check hashcat
check trufflehog
check gitleaks

echo ""
echo "=== Python libs ==="
python3 -c "import whois; print('  ✓ python-whois')"         2>/dev/null || echo -e "${RED}  ✗${NC} python-whois"
python3 -c "import shodan; print('  ✓ shodan')"               2>/dev/null || echo -e "${RED}  ✗${NC} shodan"
python3 -c "import censys; print('  ✓ censys')"               2>/dev/null || echo -e "${RED}  ✗${NC} censys"
python3 -c "import impacket; print('  ✓ impacket')"           2>/dev/null || echo -e "${RED}  ✗${NC} impacket"
python3 -c "import scapy; print('  ✓ scapy')"                 2>/dev/null || echo -e "${RED}  ✗${NC} scapy"

echo ""
echo "=== Post-exploitation ==="
warn "linpeas.sh"   "/opt/postex/linpeas.sh"
warn "winpeas.exe"  "/opt/postex/winpeas.exe"
warn "les.sh"       "/opt/postex/les.sh"
warn "goldeneye.py" "/opt/tools/bin/goldeneye.py"

echo ""
echo "=== Wordlists ==="
warn "common.txt"  "/opt/tools/wordlists/common.txt"
warn "rockyou.txt" "/opt/tools/wordlists/rockyou.txt"

echo ""
echo "──────────────────────────────"
echo -e "  ${GREEN}OK: $PASS${NC}  ${RED}MISSING: $FAIL${NC}  ${YELLOW}OPTIONAL: $WARN${NC}"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
