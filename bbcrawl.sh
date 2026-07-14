#!/usr/bin/env bash
#
#  bbcrawl.sh — all-in-one crawling & recon pipeline for bug bounty research
#  ---------------------------------------------------------------------------
#  Collects URLs (passive + active), does a MULTI-PASS deep katana crawl
#  (katana -d 2 -> feed results -> katana -d 3, going deeper each pass),
#  extracts endpoints / JS / parameters / secrets, and (optionally) runs
#  nuclei, gf patterns, sensitive-file probing and screenshots.
#
#  Every stage degrades gracefully: if a tool is missing it is skipped with a
#  warning instead of aborting the run. Re-running is safe (outputs append
#  uniquely).
#
#  Usage:   ./bbcrawl.sh -d target.com --all
#           ./bbcrawl.sh -l roots.txt -o out --depths 2,3,3 -t 60
#           ./bbcrawl.sh -d target.com --cookie 'session=..' --headless --js
#
#  ONLY run this against targets you are authorised to test (in-scope bug
#  bounty / pentest assets). You are responsible for staying in scope.
#
set -uo pipefail

# ─────────────────────────────── styling ──────────────────────────────────
if [[ -t 1 ]]; then
  R=$'\e[91m'; G=$'\e[92m'; Y=$'\e[93m'; B=$'\e[94m'; M=$'\e[95m'
  CY=$'\e[96m'; GR=$'\e[90m'; BOLD=$'\e[1m'; END=$'\e[0m'
else
  R=""; G=""; Y=""; B=""; M=""; CY=""; GR=""; BOLD=""; END=""
fi
SILENT=0
_ts() { date +%H:%M:%S; }
phase() { echo -e "\n${BOLD}${M}══[ $* ]══${END}"; }
info()  { [[ $SILENT -eq 0 ]] && echo -e "${GR}$(_ts)${END} ${B}[*]${END} $*"; }
ok()    { [[ $SILENT -eq 0 ]] && echo -e "${GR}$(_ts)${END} ${G}[+]${END} $*"; }
warn()  {              echo -e "${GR}$(_ts)${END} ${Y}[!]${END} $*"; }
err()   {              echo -e "${GR}$(_ts)${END} ${R}[x]${END} $*" >&2; }

banner() {
cat <<EOF
${CY}${BOLD}
  ┌─────────────────────────────────────────────┐
  │   bbcrawl · deep crawl & recon for bounty    │
  │   endpoints · js · params · secrets · more   │
  └─────────────────────────────────────────────┘${END}
EOF
}

# ─────────────────────────────── defaults ─────────────────────────────────
DOMAIN=""; LIST=""; OUTDIR=""
DEPTHS="2,3"          # multi-pass katana depths (the "d2 then d3" idea)
THREADS=40
RATE=150
MAX_SEEDS=2500        # cap seeds handed to deeper katana passes
HEADERS=(); COOKIE=""; PROXY=""
SCOPE_RE=""; EXCLUDE_RE=""
DO_SUBS=0; DO_PASSIVE=1; DO_ACTIVE=1; DO_JS=1; DO_SECRETS=1
DO_PARAMS=1; DO_ARJUN=0; DO_NUCLEI=0; DO_GF=0; DO_SCREENS=0; DO_DIRS=0
DO_API=1; DO_SOURCEMAPS=1; DO_CHUNKS=1; DO_REPORT=1
RESUME=0; INCREMENTAL=0
HEADLESS=0; INSECURE=0; NOTIFY=""

usage() {
  banner
cat <<EOF
${BOLD}TARGET${END}
  -d, --domain DOMAIN     single root domain / host (e.g. target.com)
  -l, --list   FILE       file of domains or URLs (one per line)
  -o, --output DIR        output dir (default: recon-<target>-<date>)

${BOLD}CRAWL${END}
      --depths  "2,3"     katana multi-pass depths, comma sep (default 2,3)
                          e.g. "2,3,3" = three passes, going deeper each time
      --max-seeds N       cap URLs seeding deeper passes (default 2500)
  -t, --threads N         concurrency (default 40)
      --rate N            max requests/sec (default 150)
      --headless          use katana headless (JS-heavy SPA sites)
  -H, --header "K: V"     extra header, repeatable (auth'd crawl)
      --cookie "c=v"      cookie header (auth'd crawl)
      --proxy URL         proxy all crawl traffic (e.g. http://127.0.0.1:8080)
  -k, --insecure          skip TLS verification

${BOLD}SCOPE${END}
      --scope   REGEX     keep only URLs matching this regex
      --exclude REGEX     drop URLs matching this regex

${BOLD}STAGES${END}  (defaults on: passive, active, js, secrets, params, api, report)
      --subs              subdomain enumeration first (subfinder/assetfinder/crt.sh)
      --arjun             active hidden-parameter discovery (arjun)
      --nuclei            nuclei exposures / misconfig / takeover scan (OFF by default,
                          NOT enabled by --all — you must ask for it explicitly)
      --gf                gf pattern extraction (xss/ssrf/sqli/lfi/redirect/...)
      --screens           screenshot live hosts (gowitness)
      --dirs              probe common sensitive files (.git/.env/etc.)
      --no-api            skip API recon (swagger/openapi/graphql/well-known/cors)
      --no-sourcemaps     skip .map source-map fetch + reconstruction
      --no-chunks         skip lazy webpack/Next chunk discovery
      --no-report         skip classification / wordlists / HTML report
      --no-passive        skip passive URL sources
      --no-active         skip active crawling
      --no-js             skip JS download/analysis
      --no-secrets        skip secret scanning
      --no-nuclei         (no-op; nuclei is already off unless --nuclei given)
      --no-params         skip parameter mining
      --all               enable every stage EXCEPT nuclei (subs+arjun+gf+screens+dirs too)
      --passive-only      only passive collection (no active crawl at all)

${BOLD}RESUME / INCREMENTAL${END}
      --resume            skip stages whose output already exists (continue an
                          interrupted run without re-crawling); re-analyses JS from
                          already-saved bodies so fixes still apply
      --incremental       report only what's NEW vs the last run of this output dir
                          (writes new_endpoints/js/secrets/subdomains.txt)

${BOLD}MISC${END}
      --notify URL        POST a summary to a Slack/Discord/Telegram webhook
      --silent            less console noise
  -h, --help              this help

${BOLD}EXAMPLES${END}
  ./bbcrawl.sh -d target.com --all
  ./bbcrawl.sh -l scope.txt --depths 2,3,3 -t 80 --gf --nuclei
  ./bbcrawl.sh -d app.target.com --cookie 'sid=..' --headless --arjun
EOF
}

# ─────────────────────────────── arg parse ────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain)   DOMAIN="$2"; shift 2;;
    -l|--list)     LIST="$2"; shift 2;;
    -o|--output)   OUTDIR="$2"; shift 2;;
    --depths)      DEPTHS="$2"; shift 2;;
    --max-seeds)   MAX_SEEDS="$2"; shift 2;;
    -t|--threads)  THREADS="$2"; shift 2;;
    --rate)        RATE="$2"; shift 2;;
    --headless)    HEADLESS=1; shift;;
    -H|--header)   HEADERS+=("$2"); shift 2;;
    --cookie)      COOKIE="$2"; shift 2;;
    --proxy)       PROXY="$2"; shift 2;;
    -k|--insecure) INSECURE=1; shift;;
    --scope)       SCOPE_RE="$2"; shift 2;;
    --exclude)     EXCLUDE_RE="$2"; shift 2;;
    --subs)        DO_SUBS=1; shift;;
    --arjun)       DO_ARJUN=1; shift;;
    --nuclei)      DO_NUCLEI=1; shift;;
    --no-nuclei)   DO_NUCLEI=0; shift;;
    --gf)          DO_GF=1; shift;;
    --screens)     DO_SCREENS=1; shift;;
    --dirs)        DO_DIRS=1; shift;;
    --no-api)      DO_API=0; shift;;
    --no-sourcemaps) DO_SOURCEMAPS=0; shift;;
    --no-chunks)   DO_CHUNKS=0; shift;;
    --no-report)   DO_REPORT=0; shift;;
    --no-passive)  DO_PASSIVE=0; shift;;
    --no-active)   DO_ACTIVE=0; shift;;
    --no-js)       DO_JS=0; shift;;
    --no-secrets)  DO_SECRETS=0; shift;;
    --no-params)   DO_PARAMS=0; shift;;
    --resume)      RESUME=1; shift;;
    --incremental) INCREMENTAL=1; shift;;
    --passive-only) DO_ACTIVE=0; DO_PASSIVE=1; shift;;
    --all)         DO_SUBS=1; DO_PASSIVE=1; DO_ACTIVE=1; DO_JS=1; DO_SECRETS=1
                   DO_PARAMS=1; DO_ARJUN=1; DO_GF=1; DO_SCREENS=1; DO_DIRS=1
                   DO_API=1; DO_SOURCEMAPS=1; DO_CHUNKS=1; DO_REPORT=1; shift;;
    --notify)      NOTIFY="$2"; shift 2;;
    --silent)      SILENT=1; shift;;
    -h|--help)     usage; exit 0;;
    *) err "unknown option: $1"; echo "run with -h for help"; exit 1;;
  esac
done

if [[ -z "$DOMAIN" && -z "$LIST" ]]; then
  usage; echo; err "provide a target with -d DOMAIN or -l FILE"; exit 1
fi

# where are the helper tools? (same dir as this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JSECRET="$SCRIPT_DIR/jsecret.py"
APIRECON="$SCRIPT_DIR/apirecon.py"
BBREPORT="$SCRIPT_DIR/bbreport.py"

# ───────────────────────────── tool helpers ───────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }
check_tool() { have "$1"; }

# dedup-append: prefer anew, else sort -u merge
dd_append() { # dd_append <destfile>   (reads stdin)
  local dest="$1"
  if have anew; then anew "$dest"; else
    cat >> "$dest.tmp"; sort -u "$dest" "$dest.tmp" 2>/dev/null -o "$dest"; rm -f "$dest.tmp"
  fi
}
# normalise + dedup a url list in place (uro strips junk/duplicate params)
normalise() { # normalise <file>
  local f="$1"
  sort -u "$f" -o "$f"
  if have uro; then uro -i "$f" 2>/dev/null > "$f.uro" && mv "$f.uro" "$f"; fi
}
countf() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

# resume helper: true when --resume and the sentinel already has data (file
# non-empty, or directory non-empty) so we can skip re-doing that work.
stage_done() { # stage_done <file-or-dir>
  [[ $RESUME -eq 1 ]] || return 1
  local p="$1"
  if [[ -d "$p" ]]; then [[ -n "$(ls -A "$p" 2>/dev/null)" ]]; return; fi
  [[ -s "$p" ]]
}
# truncate a file unless we're resuming and it already has data
fresh() { # fresh <file>
  stage_done "$1" || : > "$1"
}

katana_supports() { katana -h 2>&1 | grep -q -- "$1"; }

# ─────────────────────────────── setup ────────────────────────────────────
banner
TARGET_LABEL="${DOMAIN:-$(basename "$LIST")}"
[[ -z "$OUTDIR" ]] && OUTDIR="recon-${TARGET_LABEL//[^a-zA-Z0-9._-]/_}-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUTDIR"/{js_files,gf,screenshots,raw,.tmp}
TMP="$OUTDIR/.tmp"
info "output dir: ${BOLD}$OUTDIR${END}"

# seed target list
SEEDS="$OUTDIR/raw/seeds.txt"; : > "$SEEDS"
if [[ -n "$DOMAIN" ]]; then echo "$DOMAIN" >> "$SEEDS"; fi
if [[ -n "$LIST" ]]; then
  [[ -f "$LIST" ]] || { err "list file not found: $LIST"; exit 1; }
  cat "$LIST" >> "$SEEDS"
fi
sort -u "$SEEDS" -o "$SEEDS"
# derive registrable root domains (for crawl scoping) — strip scheme/path/port.
# handles common compound public suffixes (co.uk, com.au, co.jp, ...) so we
# don't accidentally scope to a whole public suffix like "co.uk".
COMPOUND='co\.uk|org\.uk|gov\.uk|ac\.uk|me\.uk|com\.au|net\.au|org\.au|gov\.au|edu\.au|co\.nz|org\.nz|co\.jp|or\.jp|ne\.jp|co\.za|com\.br|com\.cn|net\.cn|org\.cn|co\.in|co\.kr|com\.tr|com\.mx|com\.sg|com\.hk|com\.tw|co\.id|co\.th|com\.ua|com\.pl'
ROOTS="$TMP/roots.txt"
sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:.*$##' "$SEEDS" | \
  awk -v comp="$COMPOUND" -F. '{
    if (match($0, "(" comp ")$") && NF>=3) print $(NF-2)"."$(NF-1)"."$NF;
    else if (NF>=2) print $(NF-1)"."$NF;
    else print $0
  }' | sort -u > "$ROOTS"
ROOT_RE="$(sed 's/\./\\./g' "$ROOTS" | paste -sd'|' -)"
info "root scope: ${CY}$(paste -sd', ' "$ROOTS")${END}"

# dependency snapshot
phase "dependency check"
CORE=(katana httpx gau waybackurls subfinder assetfinder nuclei gf uro anew qsreplace unfurl gospider hakrawler paramspider arjun trufflehog jsluice gowitness)
present=(); missing=()
for t in "${CORE[@]}"; do
  if check_tool "$t"; then present+=("$t"); else missing+=("$t"); fi
done
[[ ${#present[@]} -gt 0 ]] && ok "found: ${G}${present[*]}${END}"
[[ ${#missing[@]} -gt 0 ]] && warn "missing (stages needing these are skipped): ${GR}${missing[*]}${END}"
if [[ -f "$JSECRET" ]]; then ok "jsecret.py present (regex secret/endpoint engine)"; else
  warn "jsecret.py not found next to script — JS regex analysis limited"; fi
[[ -f "$APIRECON" ]] || warn "apirecon.py not found next to script — API recon limited"
[[ -f "$BBREPORT" ]] || warn "bbreport.py not found next to script — no HTML report/wordlists"
[[ $RESUME -eq 1 ]] && ok "${CY}resume mode: stages with existing output will be skipped${END}"

# assemble shared katana flags
KFLAGS=(-c "$THREADS" -p "$THREADS" -rl "$RATE" -silent -timeout 15)
katana_supports "-jc"      && KFLAGS+=(-jc)          # crawl inside JS
katana_supports "-kf"      && KFLAGS+=(-kf all)      # robots/sitemap known files
katana_supports "-fs"      && KFLAGS+=(-fs rdn)      # stay on root domain(s)
katana_supports "-jsl"     && KFLAGS+=(-jsl)         # jsluice endpoint parsing
[[ $HEADLESS -eq 1 ]] && katana_supports "-hl" && KFLAGS+=(-hl -jc)
[[ -n "$PROXY" ]]     && KFLAGS+=(-proxy "$PROXY")
[[ $INSECURE -eq 1 ]] && KFLAGS+=(-timeout 20)
for h in "${HEADERS[@]}"; do KFLAGS+=(-H "$h"); done
[[ -n "$COOKIE" ]] && KFLAGS+=(-H "Cookie: $COOKIE")

# httpx flags
HXFLAGS=(-silent -threads "$THREADS")
[[ -n "$PROXY" ]] && HXFLAGS+=(-http-proxy "$PROXY")
for h in "${HEADERS[@]}"; do HXFLAGS+=(-H "$h"); done
[[ -n "$COOKIE" ]] && HXFLAGS+=(-H "Cookie: $COOKIE")

# ══════════════════════════ STAGE 1: subdomains ═══════════════════════════
SUBS="$OUTDIR/subdomains.txt"; fresh "$SUBS"
if [[ $DO_SUBS -eq 1 ]]; then
  phase "subdomain enumeration"
  if stage_done "$SUBS"; then
    ok "resume: keeping subdomains.txt (${BOLD}$(countf "$SUBS")${END})"
  else
  while read -r root; do
    [[ -z "$root" ]] && continue
    have subfinder   && { info "subfinder $root";   subfinder -d "$root" -silent 2>/dev/null | dd_append "$SUBS"; }
    have assetfinder && { info "assetfinder $root"; assetfinder --subs-only "$root" 2>/dev/null | dd_append "$SUBS"; }
    # free passive source: crt.sh
    info "crt.sh $root"
    curl -s --max-time 30 "https://crt.sh/?q=%25.$root&output=json" 2>/dev/null \
      | grep -oE '"name_value":"[^"]+"' | sed 's/"name_value":"//;s/"//' \
      | tr '\\n' '\n' | sed 's/\*\.//' | grep -E "\.$root$" | dd_append "$SUBS"
  done < "$ROOTS"
  ok "subdomains: ${BOLD}$(countf "$SUBS")${END} -> subdomains.txt"
  fi
else
  # no enum: seeds themselves are the hosts
  [[ -s "$SUBS" ]] || grep -vE '^\s*$' "$SEEDS" > "$SUBS"
fi

# ══════════════════════════ STAGE 2: live hosts ═══════════════════════════
LIVE="$OUTDIR/live.txt"                 # host list (bare)
LIVE_META="$OUTDIR/live_detailed.txt"   # host + status/title/tech
phase "probing live hosts"
if stage_done "$LIVE"; then
  ok "resume: keeping live.txt (${BOLD}$(countf "$LIVE")${END})"
elif have httpx; then
  httpx -l "$SUBS" "${HXFLAGS[@]}" -status-code -title -tech-detect -follow-redirects \
        -o "$LIVE_META" 2>/dev/null
  awk '{print $1}' "$LIVE_META" | sort -u > "$LIVE"
  ok "live hosts: ${BOLD}$(countf "$LIVE")${END} -> live.txt (+ live_detailed.txt)"
else
  warn "httpx missing — assuming all seeds are live (https prefixed)"
  sed -E 's#^#https://#; s#^https://https://#https://#' "$SUBS" | sort -u > "$LIVE"
fi
[[ -s "$LIVE" ]] || { warn "no live hosts resolved; falling back to raw seeds"; \
  sed -E 's#^#https://#' "$SEEDS" | sort -u > "$LIVE"; }

# ══════════════════════ STAGE 3: passive URL collection ═══════════════════
PASSIVE="$OUTDIR/raw/passive_urls.txt"; fresh "$PASSIVE"
if [[ $DO_PASSIVE -eq 1 ]]; then
  phase "passive URL collection (archives / OTX / commoncrawl)"
  if stage_done "$PASSIVE"; then
    ok "resume: keeping passive URLs (${BOLD}$(countf "$PASSIVE")${END})"
  else
  while read -r root; do
    [[ -z "$root" ]] && continue
    have gau         && { info "gau $root";         gau --threads "$THREADS" "$root" 2>/dev/null | dd_append "$PASSIVE"; }
    have waybackurls && { info "waybackurls $root"; echo "$root" | waybackurls 2>/dev/null | dd_append "$PASSIVE"; }
  done < "$ROOTS"
  # katana passive mode (pulls from wayback+commoncrawl+otx) as a booster
  if have katana && katana_supports "-passive"; then
    info "katana -passive"
    katana -list "$LIVE" -passive -silent 2>/dev/null | dd_append "$PASSIVE"
  fi
  ok "passive URLs: ${BOLD}$(countf "$PASSIVE")${END}"
  fi
fi

# ═════════════════════ STAGE 4: active DEEP crawl (multi-pass) ════════════
ACTIVE="$OUTDIR/raw/active_urls.txt"; fresh "$ACTIVE"
deep_katana() {  # the signature multi-pass: pass N output seeds pass N+1
  local seed_file="$1" out="$2"
  local input="$TMP/dk_seed.txt"
  cp "$seed_file" "$input"
  : > "$out"
  IFS=',' read -ra DARR <<< "$DEPTHS"
  local i=0
  for depth in "${DARR[@]}"; do
    i=$((i+1))
    local n; n=$(countf "$input")
    info "katana pass ${BOLD}$i${END}/${#DARR[@]}  depth=${BOLD}$depth${END}  seeds=${BOLD}$n${END}"
    local pass_out="$TMP/katana_p${i}.txt"
    katana -list "$input" -d "$depth" "${KFLAGS[@]}" -o "$pass_out" 2>/dev/null || true
    cat "$pass_out" 2>/dev/null | dd_append "$out"
    # build seeds for the next pass from THIS pass output, in-scope only, capped
    local next="$TMP/dk_next.txt"
    grep -oE 'https?://[^ ]+' "$out" 2>/dev/null \
      | { [[ -n "$ROOT_RE" ]] && grep -E "$ROOT_RE" || cat; } \
      | sort -u | head -n "$MAX_SEEDS" > "$next"
    [[ -s "$next" ]] && cp "$next" "$input"
  done
  sort -u "$out" -o "$out"
}

if [[ $DO_ACTIVE -eq 1 ]]; then
  phase "active deep crawl"
  if stage_done "$ACTIVE"; then
    ok "resume: keeping active URLs (${BOLD}$(countf "$ACTIVE")${END})"
  else
  if have katana; then
    deep_katana "$LIVE" "$TMP/katana_all.txt"
    cat "$TMP/katana_all.txt" | dd_append "$ACTIVE"
    ok "katana multi-pass URLs: ${BOLD}$(countf "$TMP/katana_all.txt")${END}"
  else
    warn "katana missing — deep crawl skipped"
  fi
  # secondary crawlers for coverage the parser misses
  if have gospider; then
    info "gospider sweep"
    GS=(-t "$THREADS" -c 10 -d 3 -q --js --sitemap --robots -a)
    [[ -n "$PROXY" ]] && GS+=(-p "$PROXY")
    [[ -n "$COOKIE" ]] && GS+=(--cookie "$COOKIE")
    gospider -S "$LIVE" "${GS[@]}" 2>/dev/null \
      | grep -oE 'https?://[^ ]+' | dd_append "$ACTIVE"
  fi
  if have hakrawler; then
    info "hakrawler sweep"
    HK=(-d 3 -subs -u)
    while read -r u; do
      echo "$u" | hakrawler "${HK[@]}" 2>/dev/null
    done < "$LIVE" | dd_append "$ACTIVE"
  fi
  ok "active URLs total: ${BOLD}$(countf "$ACTIVE")${END}"
  fi
fi

# ══════════════════════ STAGE 5: merge / normalise / scope ════════════════
phase "merge · normalise · scope"
ALL="$OUTDIR/all_urls.txt"; : > "$ALL"
cat "$PASSIVE" "$ACTIVE" 2>/dev/null | grep -E '^https?://' | sort -u >> "$ALL"
normalise "$ALL"
# scope / exclude
if [[ -n "$SCOPE_RE" ]]; then grep -E "$SCOPE_RE" "$ALL" > "$ALL.s" && mv "$ALL.s" "$ALL"; fi
if [[ -n "$ROOT_RE" && -z "$SCOPE_RE" ]]; then grep -E "$ROOT_RE" "$ALL" > "$ALL.s" && mv "$ALL.s" "$ALL"; fi
if [[ -n "$EXCLUDE_RE" ]]; then grep -vE "$EXCLUDE_RE" "$ALL" > "$ALL.s" && mv "$ALL.s" "$ALL"; fi
ok "unique in-scope URLs: ${BOLD}$(countf "$ALL")${END} -> all_urls.txt"

# ══════════════════════ STAGE 6: categorise ══════════════════════════════
phase "categorise"
ENDPOINTS="$OUTDIR/endpoints.txt"
JSLIST="$OUTDIR/js.txt"
PARAMS="$OUTDIR/params_urls.txt"
NEWSUBS="$OUTDIR/subdomains_from_crawl.txt"
INTERESTING="$OUTDIR/interesting.txt"

# all path-bearing endpoints (dedup by path), then split assets out so the route
# list isn't drowned in hashed webpack/_next chunk noise.
ASSETS="$OUTDIR/assets.txt"
if have unfurl; then unfurl -u paths < "$ALL" 2>/dev/null | sort -u > "$TMP/allpaths.txt"
else sed -E 's#^https?://[^/]+##' "$ALL" | sort -u > "$TMP/allpaths.txt"; fi
ASSET_RE='(\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|avif|mp4|webm|mp3|wav)([?#]|$))|/_next/static/|/static/chunks/'
grep -Ei  "$ASSET_RE" "$TMP/allpaths.txt" | sort -u > "$ASSETS"
grep -Eiv "$ASSET_RE" "$TMP/allpaths.txt" | sort -u > "$ENDPOINTS"
grep -iE '\.js(\?|$)' "$ALL" | sort -u > "$JSLIST"
grep -E '\?[^=]+=' "$ALL"    | sort -u > "$PARAMS"
# subdomains discovered while crawling
grep -oE 'https?://[^/]+' "$ALL" | sed -E 's#^https?://##; s#:.*$##' \
  | { [[ -n "$ROOT_RE" ]] && grep -E "$ROOT_RE" || cat; } | sort -u > "$NEWSUBS"
# high-signal endpoints worth eyeballing first
grep -iE '(/api/|/v[0-9]+/|graphql|/admin|/internal|/debug|/actuator|/swagger|/upload|/import|/redirect|/oauth|/callback|/sso|/saml|/token|/webhook|/\.git|/\.env|/backup|/config|/private|/user|/account|/payment|/invoice|/refund)' "$ALL" \
  | sort -u > "$INTERESTING"

ok "endpoints: ${BOLD}$(countf "$ENDPOINTS")${END}   js: ${BOLD}$(countf "$JSLIST")${END}   assets: ${BOLD}$(countf "$ASSETS")${END}   param-URLs: ${BOLD}$(countf "$PARAMS")${END}"
ok "crawl subdomains: ${BOLD}$(countf "$NEWSUBS")${END}   interesting: ${BOLD}$(countf "$INTERESTING")${END}"

# ══════════════════════ STAGE 7: JS download + analysis ═══════════════════
SECRETS="$OUTDIR/secrets.txt"
JS_ENDPOINTS="$OUTDIR/endpoints_from_js.txt"
JSDIR="$OUTDIR/js_files"
IDX="$JSDIR/url_index.txt"          # localpath<TAB>url  (makes findings clickable)
EPSRC="$OUTDIR/endpoints_src.tsv"   # endpoint<TAB>source (for bbreport)

# download a list of URLs into JSDIR, recording source URLs into IDX
dl_js() { # dl_js <urls-file>
  local urls="$1"; [[ -s "$urls" ]] || return 0
  if have httpx; then
    httpx -l "$urls" "${HXFLAGS[@]}" -mc 200 -srd "$JSDIR" 2>/dev/null >/dev/null || true
    [[ -f "$JSDIR/response/index.txt" ]] && cat "$JSDIR/response/index.txt" >> "$IDX"
  else
    local ju fn
    while read -r ju; do
      [[ -z "$ju" ]] && continue
      fn="$JSDIR/$(printf '%s' "$ju" | md5sum | cut -c1-16).js"
      curl -s --max-time 15 ${INSECURE:+-k} ${PROXY:+-x "$PROXY"} \
           ${COOKIE:+-H "Cookie: $COOKIE"} "$ju" -o "$fn" 2>/dev/null || true
      printf '%s\t%s\n' "$fn" "$ju" >> "$IDX"
    done < "$urls"
  fi
}
# fetch .map source maps (kept with .map extension so jsecret reconstructs them)
dl_maps() { # dl_maps <urls-file>
  local urls="$1"; [[ -s "$urls" ]] || return 0
  mkdir -p "$JSDIR/maps"; local mu fn
  while read -r mu; do
    [[ -z "$mu" ]] && continue
    fn="$JSDIR/maps/$(printf '%s' "$mu" | md5sum | cut -c1-16).map"
    curl -s --max-time 20 ${INSECURE:+-k} ${PROXY:+-x "$PROXY"} \
         ${COOKIE:+-H "Cookie: $COOKIE"} "$mu" -o "$fn" 2>/dev/null || true
    if head -c 300 "$fn" 2>/dev/null | grep -q '"sources"'; then
      printf '%s\t%s\n' "$fn" "$mu" >> "$IDX"
    else rm -f "$fn"; fi
  done < "$urls"
}

if [[ $DO_JS -eq 1 && -s "$JSLIST" ]]; then
  phase "JS download & analysis"
  if stage_done "$JSDIR"; then
    ok "resume: reusing $(find "$JSDIR" -type f 2>/dev/null | wc -l | tr -d ' ') saved JS bodies (skip download/chunks/maps)"
  else
    : > "$IDX"
    info "downloading $(countf "$JSLIST") JS files"
    dl_js "$JSLIST"
    # curl top-up if httpx saved nothing
    if [[ -z "$(find "$JSDIR" -type f ! -name url_index.txt -print -quit 2>/dev/null)" ]]; then
      idx=0
      while read -r ju; do
        idx=$((idx+1)); [[ $idx -gt 800 ]] && break
        fn="$JSDIR/$(printf '%s' "$ju" | md5sum | cut -c1-16).js"
        curl -s --max-time 15 ${INSECURE:+-k} ${PROXY:+-x "$PROXY"} \
             ${COOKIE:+-H "Cookie: $COOKIE"} "$ju" -o "$fn" 2>/dev/null || true
        printf '%s\t%s\n' "$fn" "$ju" >> "$IDX"
      done < "$JSLIST"
    fi

    # lazy-chunk discovery (webpack/Vite/Next) -> fetch + scan recursively (1 level)
    if [[ $DO_CHUNKS -eq 1 && -f "$JSECRET" ]]; then
      info "discovering lazy chunks (webpack/next)"
      base=$(head -n1 "$LIVE" 2>/dev/null)
      python3 "$JSECRET" -d "$JSDIR" --find-chunks --base-url "$base" \
        --chunks-out "$OUTDIR/raw/chunk_urls.txt" >/dev/null 2>&1 || true
      if [[ -s "$OUTDIR/raw/chunk_urls.txt" ]]; then
        grep -E '^https?://' "$OUTDIR/raw/chunk_urls.txt" \
          | { [[ -n "$ROOT_RE" ]] && grep -E "$ROOT_RE" || cat; } \
          | sort -u | head -n 1500 > "$TMP/new_chunks.txt"
        cn=$(countf "$TMP/new_chunks.txt")
        [[ $cn -gt 0 ]] && { info "fetching ${BOLD}$cn${END} discovered chunks"; dl_js "$TMP/new_chunks.txt"; }
      fi
    fi

    # source maps: try <js>.map for every JS URL, reconstruct original sources
    if [[ $DO_SOURCEMAPS -eq 1 ]]; then
      info "fetching source maps (.map)"
      sed -E 's/(\.js)([?#].*)?$/\1.map/' "$JSLIST" | grep -E '\.map$' | sort -u > "$TMP/map_urls.txt"
      dl_maps "$TMP/map_urls.txt"
      mc=$(find "$JSDIR/maps" -type f 2>/dev/null | wc -l | tr -d ' ')
      [[ "${mc:-0}" -gt 0 ]] && ok "source maps reconstructed: ${BOLD}$mc${END}"
    fi
  fi
  jscount=$(find "$JSDIR" -type f 2>/dev/null | wc -l | tr -d ' ')
  ok "JS bodies saved: ${BOLD}$jscount${END}"

  # ---- analysis always runs (cheap, local) so fixes apply even on resume ---
  : > "$SECRETS"; : > "$JS_ENDPOINTS"; : > "$EPSRC"

  # jsluice: best-in-class JS endpoint parsing (+ secrets when enabled)
  if have jsluice; then
    info "jsluice endpoint extraction"
    find "$JSDIR" -type f -print0 2>/dev/null | \
      xargs -0 -P "$THREADS" -I{} jsluice urls {} 2>/dev/null \
      | grep -oE '"url": *"[^"]+"' | sed 's/.*: *"//;s/"//' | dd_append "$JS_ENDPOINTS"
    if [[ $DO_SECRETS -eq 1 ]]; then
      info "jsluice secret extraction"
      : > "$OUTDIR/raw/jsluice_secrets.txt"
      find "$JSDIR" -type f -print0 2>/dev/null | \
        xargs -0 -P "$THREADS" -I{} jsluice secrets {} 2>/dev/null \
        | dd_append "$OUTDIR/raw/jsluice_secrets.txt"
      [[ -s "$OUTDIR/raw/jsluice_secrets.txt" ]] && \
        sed 's/^/[jsluice] /' "$OUTDIR/raw/jsluice_secrets.txt" >> "$SECRETS"
    fi
  fi

  # jsecret.py: low-noise regex engine, clickable sources, detailed endpoints
  if [[ -f "$JSECRET" ]]; then
    info "jsecret.py regex engine over saved JS + maps (clickable sources)"
    JSARGS=(-d "$JSDIR" --no-color --json "$OUTDIR/raw/jsecret.json"
            --endpoints-out "$JS_ENDPOINTS" --endpoints-detailed "$EPSRC")
    [[ -s "$IDX" ]] && JSARGS+=(--url-map "$IDX")
    if [[ $DO_SECRETS -eq 1 ]]; then JSARGS+=(--secrets-out "$SECRETS" --min-severity medium)
    else JSARGS+=(--only-endpoints); fi
    python3 "$JSECRET" "${JSARGS[@]}" >/dev/null 2>&1 || true
  fi

  # trufflehog: verified-secret scanning across the js corpus
  if [[ $DO_SECRETS -eq 1 ]] && have trufflehog; then
    info "trufflehog filesystem scan"
    trufflehog filesystem "$JSDIR" --no-update --json 2>/dev/null \
      > "$OUTDIR/raw/trufflehog.json" || true
    if [[ -s "$OUTDIR/raw/trufflehog.json" ]]; then
      grep -oE '"DetectorName":"[^"]+"' "$OUTDIR/raw/trufflehog.json" | sort | uniq -c \
        | sed 's/^/[trufflehog] /' >> "$SECRETS"
    fi
  fi

  sort -u "$JS_ENDPOINTS" -o "$JS_ENDPOINTS"
  # fold JS-derived endpoints back into the master endpoint list
  cat "$JS_ENDPOINTS" | dd_append "$ENDPOINTS"
  ok "endpoints from JS: ${BOLD}$(countf "$JS_ENDPOINTS")${END} -> endpoints_from_js.txt"
  ok "secret findings (medium+): ${BOLD}$(countf "$SECRETS")${END} -> secrets.txt (clickable)"
else
  : > "$SECRETS"; : > "$JS_ENDPOINTS"
fi

# ══════════════════════ STAGE 8: parameter mining ════════════════════════
if [[ $DO_PARAMS -eq 1 ]]; then
  phase "parameter mining"
  PARAMKEYS="$OUTDIR/param_keys.txt"
  if have unfurl; then unfurl -u keys < "$ALL" 2>/dev/null | sort -u > "$PARAMKEYS"
  else grep -oE '[?&][a-zA-Z0-9_.\-]+=' "$ALL" | tr -d '?&=' | sort -u > "$PARAMKEYS"; fi
  ok "distinct parameter names: ${BOLD}$(countf "$PARAMKEYS")${END} -> param_keys.txt"

  if have paramspider; then
    info "paramspider archive param mining"
    while read -r root; do
      [[ -z "$root" ]] && continue
      paramspider -d "$root" --quiet 2>/dev/null || true
    done < "$ROOTS"
    if [[ -d results ]]; then
      cat results/*.txt 2>/dev/null | grep -E '^https?://' | dd_append "$PARAMS"
      normalise "$PARAMS"
    fi
  fi

  if [[ $DO_ARJUN -eq 1 ]] && have arjun; then
    if stage_done "$OUTDIR/arjun_params.txt"; then
      ok "resume: keeping arjun_params.txt (${BOLD}$(countf "$OUTDIR/arjun_params.txt")${END})"
    else
    info "arjun active hidden-param discovery (sampled)"
    head -n 40 "$INTERESTING" > "$TMP/arjun_targets.txt"
    ARJ=(-i "$TMP/arjun_targets.txt" -oT "$OUTDIR/arjun_params.txt" -t "$THREADS" -q)
    [[ -n "$COOKIE" ]] && ARJ+=(--headers "Cookie: $COOKIE")
    arjun "${ARJ[@]}" 2>/dev/null || true
    [[ -f "$OUTDIR/arjun_params.txt" ]] && ok "arjun -> arjun_params.txt ($(countf "$OUTDIR/arjun_params.txt"))"
    fi
  fi
fi

# ══════════════════════ STAGE 9: gf pattern extraction ═══════════════════
if [[ $DO_GF -eq 1 ]] && have gf; then
  phase "gf vulnerability-pattern extraction"
  mapfile -t gfpat < <(gf -list 2>/dev/null)
  if [[ ${#gfpat[@]} -eq 0 ]]; then
    warn "no gf patterns installed (~/.gf) — see README to add them"
  else
    for p in xss ssrf sqli lfi rce redirect ssti idor interestingparams debug_logic; do
      printf '%s\n' "${gfpat[@]}" | grep -qx "$p" || continue
      gf "$p" < "$ALL" 2>/dev/null | sort -u > "$OUTDIR/gf/$p.txt"
      c=$(countf "$OUTDIR/gf/$p.txt"); [[ $c -gt 0 ]] && ok "gf $p: ${BOLD}$c${END} -> gf/$p.txt"
    done
  fi
fi

# ══════════════════════ STAGE 10: sensitive-file probing ══════════════════
if [[ $DO_DIRS -eq 1 ]] && have httpx; then
  phase "sensitive-file probing"
  if stage_done "$OUTDIR/sensitive_files.txt"; then
    ok "resume: keeping sensitive_files.txt (${BOLD}$(countf "$OUTDIR/sensitive_files.txt")${END})"
  else
  SENS="/.git/config,/.git/HEAD,/.env,/.env.local,/.env.production,/.aws/credentials,/config.json,/config.php,/wp-config.php.bak,/.DS_Store,/backup.zip,/backup.sql,/database.sql,/dump.sql,/.svn/entries,/server-status,/actuator/env,/actuator/heapdump,/swagger.json,/swagger-ui.html,/openapi.json,/graphql,/.well-known/security.txt,/phpinfo.php,/debug,/.htpasswd,/robots.txt,/sitemap.xml"
  httpx -l "$LIVE" "${HXFLAGS[@]}" -path "$SENS" -mc 200,301,401,403 \
        -status-code -content-length -o "$OUTDIR/sensitive_files.txt" 2>/dev/null || true
  ok "sensitive-file hits: ${BOLD}$(countf "$OUTDIR/sensitive_files.txt")${END} -> sensitive_files.txt"
  fi
fi

# ═══════════════ STAGE 10b: API recon (swagger/graphql/well-known/cors) ════
if [[ $DO_API -eq 1 && -f "$APIRECON" ]]; then
  phase "API recon (swagger · openapi · graphql · well-known · cors)"
  if stage_done "$OUTDIR/api_endpoints.txt" || stage_done "$OUTDIR/graphql_summary.txt" \
     || stage_done "$OUTDIR/cors_csp.txt"; then
    ok "resume: keeping existing API-recon output"
  else
    AR=(-l "$LIVE" -o "$OUTDIR" -t "$THREADS" --no-color)
    [[ $INSECURE -eq 1 ]] && AR+=(-k)
    [[ -n "$PROXY" ]]     && AR+=(--proxy "$PROXY")
    [[ -n "$COOKIE" ]]    && AR+=(--cookie "$COOKIE")
    for h in "${HEADERS[@]}"; do AR+=(-H "$h"); done
    python3 "$APIRECON" "${AR[@]}" 2>/dev/null || warn "apirecon failed — skipping"
    [[ -f "$OUTDIR/api_endpoints.txt" ]] && ok "api endpoints -> api_endpoints.txt (${BOLD}$(countf "$OUTDIR/api_endpoints.txt")${END})"
    [[ -f "$OUTDIR/graphql_summary.txt" ]] && ok "graphql introspection -> graphql_summary.txt"
    [[ -f "$OUTDIR/cors_csp.txt" ]] && ok "cors/csp notes -> cors_csp.txt"
  fi
fi

# ══════════════════════ STAGE 11: nuclei ═════════════════════════════════
if [[ $DO_NUCLEI -eq 1 ]] && have nuclei; then
  phase "nuclei scan (exposures · misconfig · takeover · tech)"
  if stage_done "$OUTDIR/nuclei.txt"; then
    ok "resume: keeping nuclei.txt (${BOLD}$(countf "$OUTDIR/nuclei.txt")${END})"
  else
  NU=(-silent -rl "$RATE" -o "$OUTDIR/nuclei.txt")
  [[ -n "$PROXY" ]] && NU+=(-proxy "$PROXY")
  for h in "${HEADERS[@]}"; do NU+=(-H "$h"); done
  [[ -n "$COOKIE" ]] && NU+=(-H "Cookie: $COOKIE")
  info "nuclei on live hosts"
  nuclei -l "$LIVE" -tags exposure,misconfiguration,takeover,tech,cve \
         -severity info,low,medium,high,critical "${NU[@]}" 2>/dev/null || true
  # also scan discovered JS urls for exposures
  [[ -s "$JSLIST" ]] && nuclei -l "$JSLIST" -tags exposure -silent \
         -o "$OUTDIR/nuclei_js.txt" 2>/dev/null || true
  ok "nuclei findings: ${BOLD}$(countf "$OUTDIR/nuclei.txt")${END} -> nuclei.txt"
  fi
fi

# ══════════════════════ STAGE 12: screenshots ════════════════════════════
if [[ $DO_SCREENS -eq 1 ]] && have gowitness; then
  phase "screenshots"
  if stage_done "$OUTDIR/screenshots"; then
    ok "resume: keeping existing screenshots/"
  else
  info "gowitness on live hosts"
  ( cd "$OUTDIR/screenshots" && \
    { gowitness scan file -f "../live.txt" 2>/dev/null \
      || gowitness file -f "../live.txt" 2>/dev/null; } ) || \
    warn "gowitness run failed (version/flags) — skipping"
  ok "screenshots -> screenshots/"
  fi
fi

# ═══════════════ STAGE 13: classify · score · wordlists · HTML report ══════
if [[ $DO_REPORT -eq 1 && -f "$BBREPORT" ]]; then
  phase "report (classify · risk-score · wordlists · HTML)"
  BR=(-o "$OUTDIR")
  [[ $INCREMENTAL -eq 1 ]] || BR+=(--no-incremental)
  python3 "$BBREPORT" "${BR[@]}" 2>/dev/null || warn "bbreport failed — skipping"
  [[ -f "$OUTDIR/report.html" ]] && ok "HTML report -> ${BOLD}report.html${END}   prioritised -> prioritized_endpoints.txt   wordlists -> wordlist_*.txt"
fi

# ══════════════════════════════ SUMMARY ═══════════════════════════════════
phase "summary"
SUMMARY="$OUTDIR/SUMMARY.txt"
{
  echo "bbcrawl summary — $(date)"
  echo "target(s): $(paste -sd', ' "$SEEDS")"
  echo "output:    $OUTDIR"
  echo "depths:    $DEPTHS"
  echo "-------------------------------------------"
  printf "%-28s %s\n" "subdomains"            "$(countf "$SUBS")"
  printf "%-28s %s\n" "live hosts"            "$(countf "$LIVE")"
  printf "%-28s %s\n" "all urls (in-scope)"   "$(countf "$ALL")"
  printf "%-28s %s\n" "endpoints"             "$(countf "$ENDPOINTS")"
  printf "%-28s %s\n" "js files"              "$(countf "$JSLIST")"
  printf "%-28s %s\n" "endpoints from js"     "$(countf "$JS_ENDPOINTS")"
  printf "%-28s %s\n" "param urls"            "$(countf "$PARAMS")"
  printf "%-28s %s\n" "distinct param names"  "$(countf "$OUTDIR/param_keys.txt")"
  printf "%-28s %s\n" "interesting endpoints" "$(countf "$INTERESTING")"
  printf "%-28s %s\n" "secret findings"       "$(countf "$SECRETS")"
  [[ -f "$OUTDIR/api_endpoints.txt" ]]   && printf "%-28s %s\n" "api endpoints (spec)"  "$(countf "$OUTDIR/api_endpoints.txt")"
  [[ -f "$OUTDIR/prioritized_endpoints.txt" ]] && printf "%-28s %s\n" "prioritised endpoints" "$(countf "$OUTDIR/prioritized_endpoints.txt")"
  [[ -f "$OUTDIR/assets.txt" ]]          && printf "%-28s %s\n" "static assets (split out)" "$(countf "$OUTDIR/assets.txt")"
  [[ -f "$OUTDIR/sensitive_files.txt" ]] && printf "%-28s %s\n" "sensitive-file hits" "$(countf "$OUTDIR/sensitive_files.txt")"
  [[ -f "$OUTDIR/nuclei.txt" ]]          && printf "%-28s %s\n" "nuclei findings"     "$(countf "$OUTDIR/nuclei.txt")"
  if [[ -d "$OUTDIR/gf" ]]; then
    for f in "$OUTDIR"/gf/*.txt; do [[ -e "$f" ]] || continue
      printf "%-28s %s\n" "gf $(basename "$f" .txt)" "$(countf "$f")"; done
  fi
  if [[ $INCREMENTAL -eq 1 ]]; then
    for nf in new_endpoints new_js new_secrets new_subdomains; do
      [[ -f "$OUTDIR/$nf.txt" ]] && printf "%-28s %s\n" "$nf" "$(countf "$OUTDIR/$nf.txt")"
    done
  fi
  echo "-------------------------------------------"
  hi=$(grep -icE '^\[high\]|high' "$SECRETS" 2>/dev/null); hi=${hi:-0}
  echo "high-severity secret lines: $hi"
  echo "open first:  report.html  (clickable secrets + prioritised endpoints)"
  echo "review next: prioritized_endpoints.txt, secrets.txt, api_endpoints.txt, interesting.txt"
} | tee "$SUMMARY"

if [[ -s "$SECRETS" ]]; then
  echo -e "\n${BOLD}${R}top secret findings:${END}"
  grep -iE 'high|AWS|Stripe|GitHub|Google|Slack|Private Key|Token|mongodb|password' "$SECRETS" | head -n 15
fi

# optional webhook notification
if [[ -n "$NOTIFY" ]]; then
  msg="bbcrawl done for $(paste -sd', ' "$SEEDS") | live=$(countf "$LIVE") urls=$(countf "$ALL") js=$(countf "$JSLIST") secrets=$(countf "$SECRETS") interesting=$(countf "$INTERESTING")"
  case "$NOTIFY" in
    *hooks.slack.com*) curl -s -X POST -H 'Content-type: application/json' \
        -d "{\"text\":\"$msg\"}" "$NOTIFY" >/dev/null 2>&1 ;;
    *discord.com/api/webhooks*) curl -s -X POST -H 'Content-type: application/json' \
        -d "{\"content\":\"$msg\"}" "$NOTIFY" >/dev/null 2>&1 ;;
    *api.telegram.org*) curl -s "$NOTIFY" --data-urlencode "text=$msg" >/dev/null 2>&1 ;;
    *) curl -s -X POST -d "$msg" "$NOTIFY" >/dev/null 2>&1 ;;
  esac
  ok "summary pushed to webhook"
fi

# tidy temp
rm -rf "$TMP"
echo -e "\n${BOLD}${G}✔ done${END} — everything under ${BOLD}$OUTDIR/${END}"
echo -e "${GR}reminder: only act on findings for assets you're authorised to test.${END}"
