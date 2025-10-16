
FROM golang:1.24-bookworm AS gobuild

# Allow forward toolchain switching if a module requests it
ENV GOTOOLCHAIN=auto \
    CGO_ENABLED=0 \
    GO111MODULE=on \
    GOPATH=/go

WORKDIR /build

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install -v github.com/owasp-amass/amass/v4/...@latest
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest
    go install -v github.com/hahwul/dalfox/v2@latest
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/Brosck/mantra@latest
RUN git clone https://github.com/assetnote/kiterunner.git && \
    cd kiterunner && \
    go build -o /go/bin/kr ./cmd/kiterunner/main.go

FROM rust:1.83-bullseye AS rustbuild
RUN cargo install --locked --version 2.4.1 rustscan

FROM debian:bookworm-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl wget bash git jq nmap unzip \
      python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/pytools \
 && /opt/pytools/bin/pip install --no-cache-dir --upgrade pip setuptools wheel

COPY --from=gobuild /go/bin/* /usr/local/bin/
COPY --from=rustbuild /usr/local/cargo/bin/rustscan /usr/local/bin/rustscan

RUN set -eux; \
    mkdir -p /opt/tools; \
    git clone --depth 1 https://github.com/GerbenJavado/LinkFinder /opt/tools/LinkFinder; \
    /opt/pytools/bin/pip install --no-cache-dir -r /opt/tools/LinkFinder/requirements.txt; \
    git clone --depth 1 https://github.com/s0md3v/XSStrike /opt/tools/XSStrike; \
    /opt/pytools/bin/pip install --no-cache-dir -r /opt/tools/XSStrike/requirements.txt; \
    git clone --depth 1 https://github.com/pwn0sec/PwnXSS /opt/tools/PwnXSS; \
    /opt/pytools/bin/pip install --no-cache-dir beautifulsoup4 requests
RUN printf '#!/usr/bin/env bash\nexec /opt/pytools/bin/python /opt/tools/LinkFinder/linkfinder.py "$@"\n' \
      > /usr/local/bin/linkfinder && chmod +x /usr/local/bin/linkfinder \
 && printf '#!/usr/bin/env bash\nexec /opt/pytools/bin/python /opt/tools/XSStrike/xsstrike.py "$@"\n' \
      > /usr/local/bin/xsstrike && chmod +x /usr/local/bin/xsstrike \
 && printf '#!/usr/bin/env bash\nexec /opt/pytools/bin/python /opt/tools/PwnXSS/pwnxss.py "$@"\n' \
      > /usr/local/bin/pwnxss && chmod +x /usr/local/bin/pwnxss
ENV PATH="/opt/pytools/bin:${PATH}"

# Nuclei-bug-hunter templates 
RUN git clone --depth 1 https://github.com/ayadim/Nuclei-bug-hunter.git /opt/Nuclei-bug-hunter || true

# Subfinder config dir
RUN mkdir -p /work /root/.config/subfinder
WORKDIR /work

COPY lazyrecon-plus.sh /usr/local/bin/lazyrecon-plus.sh
COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/lazyrecon-plus.sh /usr/local/bin/entrypoint.sh

# Default ENV (override with -e at runtime)
ENV THREADS=30 RATE=200 NUCLEI_RATE=300 \
    LINKFINDER_DIR=/opt/tools/LinkFinder \
    XSSTRIKE_DIR=/opt/tools/XSStrike \
    PWNXSS_DIR=/opt/tools/PwnXSS \
    NUCLEI_BUGHUNTER_DIR=/opt/Nuclei-bug-hunter

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--help"]
