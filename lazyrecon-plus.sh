#!/usr/bin/env bash

set -Eeuo pipefail
shopt -s nullglob

THREADS=${THREADS:-30}
RATE=${RATE:-200}
NUCLEI_RATE=${NUCLEI_RATE:-300}
OUT_ROOT=${OUT_ROOT:-/work/results}
WORDLIST_API=${WORDLIST_API:-apiroutes}
KR_DEPTH=${KR_DEPTH:-2}
TIMEOUT=${TIMEOUT:-10}
AMASS_TIMEOUT=${AMASS_TIMEOUT:-300}

LINKFINDER_DIR=${LINKFINDER_DIR:-/opt/tools/LinkFinder}
XSSTRIKE_DIR=${XSSTRIKE_DIR:-/opt/tools/XSStrike}
PWNXSS_DIR=${PWNXSS_DIR:-/opt/tools/PwnXSS}
NUCLEI_BUGHUNTER_DIR=${NUCLEI_BUGHUNTER_DIR:-/opt/Nuclei-bug-hunter}

SOURCE_CODE_DIR="${SOURCE_CODE_DIR:-}"
GITHUB_ORG="${GITHUB_ORG:-}"

log(){ printf "[+] %s\n" "$*"; }
err(){ printf "[!] %s\n" "$*" >&2; }

usage(){ cat <<USAGE
Usage: $0 [-d domain] [-l domain_list] [-o out_dir] [--threads N] [--rate N]
          [--src /path/to/source] [--gh-org org] [--nuclei-templates /opt/Nuclei-bug-hunter]
USAGE
}

DOMAINS=(); LIST_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAINS+=("$2"); shift 2 ;;
    -l|--list) LIST_FILE="$2"; shift 2 ;;
    -o|--out) OUT_ROOT="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    --src) SOURCE_CODE_DIR="$2"; shift 2 ;;
    --gh-org) GITHUB_ORG="$2"; shift 2 ;;
    --nuclei-templates) NUCLEI_BUGHUNTER_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

if [[ -n "${LIST_FILE}" ]]; then
  mapfile -t list_domains < <(grep -vE '^\s*(#|$)' "${LIST_FILE}" | tr -d '\r')
  DOMAINS+=("${list_domains[@]}")
fi

[[ ${#DOMAINS[@]} -gt 0 ]] || { err "No domains provided"; usage; exit 1; }

mkdir -p "${OUT_ROOT}"
START_TS=$(date -Is)

need(){ command -v "$1" >/dev/null 2>&1 || { err "Missing required tool: $1"; exit 2; }; }
for bin in subfinder assetfinder amass httpx nuclei rustscan nmap kr dalfox jq curl; do
  need "$bin" || true
done

command -v noir >/dev/null 2>&1 || true
command -v kingfisher >/dev/null 2>&1 || true

[[ -f "${LINKFINDER_DIR}/linkfinder.py" ]] || true
[[ -f "${XSSTRIKE_DIR}/xsstrike.py" ]] || true
[[ -f "${PWNXSS_DIR}/pwnxss.py" ]] || true

# RECON + REPORT 

recon_domain(){
  local domain="$1"
  local outdir="${OUT_ROOT}/${domain}"
  mkdir -p "${outdir}"/{subdomains,hosts,urls,scans,nuclei,js,api,report,artifacts,secrets}

  log "Enumerating subdomains for ${domain}"
  subfinder -silent -timeout "${TIMEOUT}" -t "${THREADS}" -d "${domain}" -o "${outdir}/subdomains/subfinder.txt" || true
  assetfinder --subs-only "${domain}" | sed 's/\r$//' | sort -u > "${outdir}/subdomains/assetfinder.txt" || true
  log "Running Amass (timeout ${AMASS_TIMEOUT}s)"
  timeout --preserve-status "${AMASS_TIMEOUT}"s \
    amass enum -passive -d "${domain}" -o "${outdir}/subdomains/amass.txt" || true

  cat "${outdir}"/subdomains/*.txt 2>/dev/null | sed 's/^\*\.//' | sort -u > "${outdir}/subdomains/all.txt"
  log "$(wc -l < "${outdir}/subdomains/all.txt" 2>/dev/null) unique subdomains"

  log "Probing for live HTTP(S) hosts"
  httpx -silent -l "${outdir}/subdomains/all.txt" -timeout "${TIMEOUT}" -threads "${THREADS}" \
        -follow-redirects -status-code -title -ip -o "${outdir}/hosts/live.txt" || true
  cut -d ' ' -f1 "${outdir}/hosts/live.txt" > "${outdir}/hosts/live_urls.txt"
  awk '{print $NF}' "${outdir}/hosts/live.txt" | tr -d '[]' | sort -u > "${outdir}/hosts/ips.txt"

  log "Port scanning with rustscan -> nmap"
  if [[ -s "${outdir}/hosts/ips.txt" ]]; then
    rustscan -a "$(paste -sd, "${outdir}/hosts/ips.txt")" --ulimit 5000 -- -sV -sC -Pn -oA "${outdir}/scans/nmap_rustscan" || true
  fi

  if command -v waybackurls >/dev/null 2>&1; then
    log "Pulling Wayback Machine URLs"
    cat "${outdir}/subdomains/all.txt" | waybackurls > "${outdir}/urls/wayback.txt" || true
  fi
  if command -v gau >/dev/null 2>&1; then
    log "Pulling gau URLs"
    gau --threads "${THREADS}" --o "${outdir}/urls/gau.txt" "${domain}" || true
  fi
  cat "${outdir}/urls/"*.txt 2>/dev/null | sort -u > "${outdir}/urls/all_urls.txt" || true

  if [[ -f "${LINKFINDER_DIR}/linkfinder.py" ]]; then
    log "Running LinkFinder to extract endpoints from JS"
    while read -r url; do
      python3 "${LINKFINDER_DIR}/linkfinder.py" -i "${url}" -o cli 2>/dev/null || true
    done < "${outdir}/hosts/live_urls.txt" | sort -u > "${outdir}/js/linkfinder_endpoints.txt" || true
  fi

  if command -v kr >/dev/null 2>&1; then
    log "Kiterunner API route bruteforce (depth=${KR_DEPTH}, list=${WORDLIST_API})"
    kr scan "@${outdir}/hosts/live_urls.txt" -A="${WORDLIST_API}" -d "${KR_DEPTH}" --ignore-length 0 -x 8 -j 50 \
      > "${outdir}/api/kiterunner.ndjson" || true
  fi

  if [[ -d "${NUCLEI_BUGHUNTER_DIR}" ]]; then
    log "Running Nuclei with Bug Hunter templates"
    nuclei -silent -l "${outdir}/hosts/live_urls.txt" -t "${NUCLEI_BUGHUNTER_DIR}" -rl "${NUCLEI_RATE}" \
      -o "${outdir}/nuclei/bughunter-findings.txt" || true
  fi

  URL_INPUT="${outdir}/urls/all_urls.txt"
  [[ -s "${URL_INPUT}" ]] || URL_INPUT="${outdir}/hosts/live_urls.txt"

  if command -v dalfox >/dev/null 2>&1 && [[ -s "${URL_INPUT}" ]]; then
    log "Dalfox pipe over discovered URLs"
    cat "${URL_INPUT}" | dalfox pipe --silence --only-poc --follow-redirects --timeout "${TIMEOUT}" \
      --output "${outdir}/scans/dalfox.txt" || true
  fi

  if [[ -f "${XSSTRIKE_DIR}/xsstrike.py" && -s "${URL_INPUT}" ]]; then
    log "XSStrike over a sampled set of URLs"
    head -n 200 "${URL_INPUT}" | while read -r u; do
      python3 "${XSSTRIKE_DIR}/xsstrike.py" -u "${u}" --skip-dom --threads 10 --timeout "${TIMEOUT}" 2>/dev/null || true
    done | tee "${outdir}/scans/xsstrike.txt" >/dev/null
  fi

  if [[ -f "${PWNXSS_DIR}/pwnxss.py" && -s "${URL_INPUT}" ]]; then
    log "PwnXSS over a sampled set of URLs"
    head -n 100 "${URL_INPUT}" | while read -r u; do
      python3 "${PWNXSS_DIR}/pwnxss.py" -u "${u}" 2>/dev/null || true
    done | tee "${outdir}/scans/pwnxss.txt" >/dev/null
  fi

  if command -v Mantra >/dev/null 2>&1; then
    log "Scanning for API key leaks with Mantra"
    while read -r u; do
      Mantra -u "${u}" 2>/dev/null || true
    done < "${outdir}/hosts/live_urls.txt" | tee "${outdir}/secrets/mantra.txt" >/dev/null
  fi

  if command -v noir >/dev/null 2>&1 && [[ -n "${SOURCE_CODE_DIR}" && -d "${SOURCE_CODE_DIR}" ]]; then
    log "Running OWASP Noir on source code to extract endpoints"
    noir -b "${SOURCE_CODE_DIR}" -u "https://${domain}" -f json > "${outdir}/api/noir.json" || true
  fi

  if command -v kingfisher >/dev/null 2>&1; then
    log "Running kingfisher for secret scanning (local artifacts)"
    mkdir -p "${outdir}/artifacts/web"
    while read -r u; do
      curl -m "${TIMEOUT}" -sL "${u}" -o "${outdir}/artifacts/web/$(echo "${u}" | sed 's#[^a-zA-Z0-9]#_#g').html" || true
    done < "${outdir}/hosts/live_urls.txt"
    kingfisher scan --path "${outdir}/artifacts/web" --format json > "${outdir}/secrets/kingfisher.json" 2>/dev/null || true
    if [[ -n "${GITHUB_ORG}" ]]; then
      log "Scanning GitHub org ${GITHUB_ORG} for exposed secrets"
      kingfisher scan --github-org "${GITHUB_ORG}" --format json > "${outdir}/secrets/kingfisher-github.json" 2>/dev/null || true
    fi
  fi

  generate_report "${domain}" "${outdir}"
}

generate_report(){
  local domain="$1"; local outdir="$2"
  local report="${outdir}/report/index.html"
  log "Generating HTML report for ${domain} -> ${report}"

  local subs_count=$(wc -l < "${outdir}/subdomains/all.txt" 2>/dev/null || echo 0)
  local live_count=$(wc -l < "${outdir}/hosts/live_urls.txt" 2>/dev/null || echo 0)
  local nuclei_count=$(wc -l < "${outdir}/nuclei/bughunter-findings.txt" 2>/dev/null || echo 0)

  cat > "${report}" <<HTML
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon Report — ${domain}</title>
<style>
 body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",Arial;padding:24px;}
 h1,h2{margin:0.2em 0;} .pill{display:inline-block;padding:2px 8px;border-radius:12px;background:#eef;} .sec{margin-top:22px;}
 pre{background:#0b1021;color:#f0f3f6;padding:10px;border-radius:6px;white-space:pre-wrap;word-wrap:break-word;}
 a{color:#0645AD;} table{border-collapse:collapse;width:100%;} td,th{border:1px solid #ddd;padding:6px;} th{background:#f6f8fa;text-align:left}
 details{border:1px solid #ddd;border-radius:6px;padding:8px;margin:8px 0;background:#fafbfc}
 .k{color:#0a7;} .crit{color:#b00020} .hi{color:#b36b00}
</style></head><body>
<h1>Recon Report — ${domain}</h1>
<p class="pill">Generated: ${START_TS}</p>
<div class="sec">
  <h2>Overview</h2>
  <ul>
    <li>Total subdomains: <b>${subs_count}</b></li>
    <li>Live HTTP(S) hosts: <b>${live_count}</b></li>
    <li>Nuclei (Bug Hunter) findings: <b>${nuclei_count}</b></li>
  </ul>
</div>
<div class="sec"><h2>Subdomains</h2>
  <p>Files: ../subdomains/all.txtall.txt</a>, <a href="../subdomains/subfinder.txt</a>, <a/subdomains/assetfinder.txtassetfinder</a>, <a href="../subdomains/amass.txt</p>
  <details><summary>Preview (first 100)</summary><pre>$(head -n 100 "${outdir}/subdomains/all.txt" 2>/dev/null)</pre></details>
</div>
<div class="sec"><h2>Live Hosts & Ports</h2>
  <p>Live URLs: ../hosts/live_urls.txtlive_urls.txt</a> — IPs: ../hosts/ips.txtips.txt</a></p>
  <p>Nmap (via rustscan): ../scans/nmap_rustscan.nmapnmap</a> | ../scans/nmap_rustscan.gnmapgnmap</a> | ../scans/nmap_rustscan.xmlxml</a></p>
</div>
<div class="sec"><h2>API & Endpoint Discovery</h2>
  <p>Kiterunner NDJSON: <a href="../unner.ndjsonkiterunner.ndjson</a></p>
  <p>LinkFinder endpoints: ../js/linkfinder_endpoints.txtlinkfinder_endpoints.txt</a></p>
  $( [[ -f "${outdir}/api/noir.json" ]] && echo "<p>Noir (whitebox) JSON: <a href=\"../api/noir.json\">noir.json</a></p>" )
</div>
<div class="sec"><h2>Vulnerability Scanning</h2>
  <p>Nuclei (Bug Hunter): <a href="../nuclei/-findings.txtfindings</a></p>
  <p>Dalfox (XSS): <a href="../scans/dalfoxx.txt</a></p>
  <p>XSStrike output: <a href="../scans/xsstrike.txttxt</a> — PwnXSS: <a href="../scans/pwnxsss.txt</a></p>
</div>
<div class="sec"><h2>Secrets & Leaks</h2>
  <p>Mantra: ../secrets/mantra.txtmantra.txt</a></p>
  $( [[ -f "${outdir}/secrets/kingfisher.json" ]] && echo "<p>Kingfisher (local artifacts): <a href=\"../secrets/kingfisher.json\">kingfisher.json</a></p>" )
  $( [[ -f "${outdir}/secrets/kingfisher-github.json" ]] && echo "<p>Kingfisher (GitHub org): <a href=\"../secrets/kingfisher-github.json\">kingfisher-github.json</a></p>" )
</div>
<div class="sec"><h2>URL Corpus</h2>
  <p>All URLs: ../urls/all_urls.txtall_urls.txt</a></p>
  $( [[ -f "${outdir}/urls/wayback.txt" ]] && echo "<p>Wayback: <a href=\"../urls/wayback.txt\">wayback.txt</a></p>" )
  $( [[ -f "${outdir}/urls/gau.txt" ]] && echo "<p>gau: <a href=\"../urls/gau.txt\">gau.txt</a></p>" )
</div>
<hr><p><small>lazyrecon-plus (Docker) — generated automatically.</small></p>
</body></html>
HTML
}

log "Starting recon for ${#DOMAINS[@]} domain(s): ${DOMAINS[*]}"
for d in "${DOMAINS[@]}"; do
  recon_domain "$d"
  log "Done: $d"; echo
done
log "All done. Consolidated results under: ${OUT_ROOT}"
