# PentraScan — Scanner Container
# Base: Kali Linux rolling
# Architecture: multi-stage to keep layers cacheable
# platform: linux/amd64 (set in docker-compose)

FROM kalilinux/kali-rolling:latest AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOPATH=/root/go \
    PATH="/root/go/bin:/usr/local/go/bin:/opt/tools/bin:$PATH"

# ── Layer 1: System packages ───────────────────────────────────────────────
# Replace sources.list to avoid unreachable mirrors (neusoft, etc.)
RUN printf '%s\n%s\n' \
    'deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware' \
    'deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware' \
    > /etc/apt/sources.list && \
    rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources && \
    rm -f /etc/apt/apt.conf.d/99block-neusoft && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    curl wget git vim nano unzip p7zip-full tar gzip \
    ca-certificates gnupg lsb-release apt-transport-https \
    python3 python3-venv python3-dev \
    build-essential libssl-dev libffi-dev libxml2-dev libxslt1-dev \
    nmap masscan hping3 netdiscover arp-scan \
    tcpdump tshark net-tools iputils-ping \
    traceroute whois dnsutils \
    nikto sqlmap gobuster \
    wafw00f whatweb \
    sslscan \
    hydra medusa ncrack \
    john hashcat \
    nbtscan \
    theharvester recon-ng dnsrecon fierce \
    jq bc expect \
    && rm -rf /var/lib/apt/lists/*

# ── Layer 2: Python tools ──────────────────────────────────────────────────
RUN curl -fsSL https://bootstrap.pypa.io/get-pip.py | python3 - --break-system-packages && \
    pip3 install --no-cache-dir --break-system-packages \
    python-whois \
    shodan \
    censys \
    impacket \
    pwntools \
    scapy \
    requests \
    dnspython \
    paramiko \
    netaddr \
    tqdm \
    colorama \
    rich \
    dirsearch \
    sslyze \
    smbmap \
    enum4linux

# ── Layer 3: Go installation ───────────────────────────────────────────────
RUN arch=$(uname -m) && \
    case "$arch" in \
      aarch64|arm64) GOARCH=arm64 ;; \
      *) GOARCH=amd64 ;; \
    esac && \
    curl -fsSL "https://go.dev/dl/go1.22.3.linux-${GOARCH}.tar.gz" \
    | tar -C /usr/local -xzf - \
    && ln -sf /usr/local/go/bin/go /usr/local/bin/go

# ── Layer 4: Go-based tools ────────────────────────────────────────────────
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || true && \
    go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null || true && \
    go install -v github.com/OJ/gobuster/v3@latest 2>/dev/null || true && \
    go install -v github.com/tomnomnom/assetfinder@latest 2>/dev/null || true && \
    go install -v github.com/tomnomnom/waybackurls@latest 2>/dev/null || true && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true && \
    go install -v github.com/hakluke/hakrawler@latest 2>/dev/null || true && \
    go install -v github.com/hahwul/dalfox/v2@latest 2>/dev/null || true && \
    go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest 2>/dev/null || true && \
    go install -v github.com/sensepost/gowitness@latest 2>/dev/null || true && \
    go install -v github.com/ropnop/kerbrute@latest 2>/dev/null || true && \
    go install -v github.com/trufflesecurity/trufflehog/v3@latest 2>/dev/null || true && \
    go install -v github.com/gitleaks/gitleaks/v8@latest 2>/dev/null || true && \
    go install -v github.com/s0md3v/arjun@latest 2>/dev/null || true && \
    go install -v github.com/evilsocket/pwnagotchi@latest 2>/dev/null || true || true

# ── Layer 5: Manual tool downloads ────────────────────────────────────────
RUN mkdir -p /opt/tools/bin /opt/tools/wordlists /opt/postex

# rustscan (fast port scanner)
RUN arch=$(uname -m) && \
    case "$arch" in aarch64|arm64) DEB=arm64 ;; *) DEB=amd64 ;; esac && \
    curl -fsSL "https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_${DEB}.deb" \
    -o /tmp/rustscan.deb && dpkg -i /tmp/rustscan.deb || true && rm -f /tmp/rustscan.deb

# feroxbuster (recursive dir brute)
RUN arch=$(uname -m) && \
    case "$arch" in aarch64|arm64) DEB=arm64 ;; *) DEB=amd64 ;; esac && \
    curl -fsSL "https://github.com/epi052/feroxbuster/releases/download/v2.10.4/feroxbuster_${DEB}.deb" \
    -o /tmp/ferox.deb && dpkg -i /tmp/ferox.deb || true && rm -f /tmp/ferox.deb

# pspy64 (process spy, no-root) — binary from GitHub, not in apt
RUN curl -fsSL "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" \
    -o /opt/tools/bin/pspy64 && chmod +x /opt/tools/bin/pspy64 || true

# nuclei templates
RUN nuclei -update-templates -silent 2>/dev/null || true

# ── Layer 6: Post-exploitation scripts ────────────────────────────────────
RUN \
    # LinPEAS
    curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh \
        -o /opt/postex/linpeas.sh && chmod +x /opt/postex/linpeas.sh || true && \
    # WinPEAS
    curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe \
        -o /opt/postex/winpeas.exe || true && \
    # linux-exploit-suggester
    curl -fsSL https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh \
        -o /opt/postex/les.sh && chmod +x /opt/postex/les.sh || true && \
    # GoldenEye (HTTP DoS)
    curl -fsSL https://raw.githubusercontent.com/jseidl/GoldenEye/master/goldeneye.py \
        -o /opt/tools/bin/goldeneye.py && chmod +x /opt/tools/bin/goldeneye.py || true

# ── Layer 7: Wordlists ─────────────────────────────────────────────────────
RUN \
    # SecLists subset (common dirs + passwords)
    git clone --depth=1 --filter=blob:none --sparse \
        https://github.com/danielmiessler/SecLists.git /opt/tools/wordlists/seclists 2>/dev/null && \
    cd /opt/tools/wordlists/seclists && \
    git sparse-checkout set \
        Discovery/Web-Content/common.txt \
        Discovery/Web-Content/directory-list-2.3-medium.txt \
        Discovery/DNS/subdomains-top1million-5000.txt \
        Passwords/Leaked-Databases/rockyou-75.txt \
        Usernames/top-usernames-shortlist.txt \
    2>/dev/null || true && \
    # Symlinks for convenience
    ln -sf /opt/tools/wordlists/seclists/Discovery/Web-Content/common.txt \
        /opt/tools/wordlists/common.txt || true && \
    ln -sf /opt/tools/wordlists/seclists/Passwords/Leaked-Databases/rockyou-75.txt \
        /opt/tools/wordlists/rockyou.txt || true

# ── Layer 8: App code ──────────────────────────────────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

# ── Health check ───────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)"

CMD ["celery", "-A", "app.worker", "worker", \
     "--loglevel=info", "--queues=scans", \
     "--concurrency=2", "--pool=prefork"]
