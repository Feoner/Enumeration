
FROM golang:1.24-bookworm AS gobuild

ENV CGO_ENABLED=0 \
    GO111MODULE=on \
    GOPATH=/go

# Build dirs
WORKDIR /build

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install -v github.com/owasp-amass/amass/v4/...@latest
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest
    go install -v github.com/hahwul/dalfox/v2@latest
    git clone https://github.com/assetnote/kiterunner.git && \
    cd kiterunner && \
    go build -o /go/bin/kr ./cmd/kiterunner/main.go && \
    cd /build && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/MrEmpy/Mantra@latest

FROM debian:bookworm-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl wget bash git jq nmap unzip \
      python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*


FROM rust:1.80-bullseye AS rustbuild
RUN cargo install rustscan


# Copy go and rust tools
COPY --from=gobuild /go/bin/* /usr/local/bin/
COPY --from=rustbuild /usr/local/cargo/bin/rustscan /usr/local/bin/rustscan


# Python tools: LinkFinder, XSStrike, PwnXSS
RUN mkdir -p /opt/tools && \
    git clone https://github.com/GerbenJavado/LinkFinder /opt/tools/LinkFinder && \
    pip3 install -r /opt/tools/LinkFinder/requirements.txt && \
    git clone https://github.com/s0md3v/XSStrike /opt/tools/XSStrike && \
    pip3 install -r /opt/tools/XSStrike/requirements.txt && \
    git clone https://github.com/pwn0sec/PwnXSS /opt/tools/PwnXSS && \
    pip3 install beautifulsoup4 requests

# Nuclei-bug-hunter templates 
RUN git clone --depth 1 https://github.com/ayadim/Nuclei-bug-hunter.git /opt/Nuclei-bug-hunter || true

# Optional: pre-warm Kiterunner wordlists cache (downloads on first run otherwise)
# RUN kr wordlist list >/dev/null 2>&1 || true

# Create workspace
RUN mkdir -p /work && mkdir -p /root/.config/subfinder
WORKDIR /work

# Copy the orchestrator and entrypoint
COPY lazyrecon-plus.sh /usr/local/bin/lazyrecon-plus.sh
COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/lazyrecon-plus.sh /usr/local/bin/entrypoint.sh

# Non-root user for safety (comment out if you need root)
# RUN useradd -ms /bin/bash runner && chown -R runner:runner /work /opt
# USER runner
 (override with -e)
ENV THREADS=30 RATE=200 NUCLEI_RATE=300 \
    LINKFINDER_DIR=/opt/tools/LinkFinder \
    XSSTRIKE_DIR=/opt/tools/XSStrike \
    PWNXSS_DIR=/opt/tools/PwnXSS \
    NUCLEI_BUGHUNTER_DIR=/opt/Nuclei-bug-hunter


ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--help"]
