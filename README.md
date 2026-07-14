# bbcrawl — all-in-one deep crawler & recon for bug bounty

Crawl a target as deeply as possible and pull out everything worth looking at:
**endpoints, JS files, endpoints hidden inside JS, parameters, and secrets** —
then reconstruct **source maps**, discover **lazy-loaded webpack/Next chunks**,
enumerate the **API surface** (Swagger/OpenAPI + GraphQL introspection +
well-known artifacts + CORS/CSP), **classify and risk-score** every endpoint, and
drop a single **clickable HTML report** plus ready-to-use **ffuf wordlists**. It
wraps the standard recon toolchain and adds a **multi-pass "deep katana" crawl**
(the `katana -d 2` → feed output → `katana -d 3` idea) so later passes treat
earlier discoveries as fresh roots and reach much deeper than a single crawl.

Optional `gf` vuln-pattern extraction, sensitive-file probing, screenshots, and
`nuclei` are available too — **`nuclei` is off by default and is *not* enabled by
`--all`; you must pass `--nuclei` explicitly.**

> ⚠️ **Only run this against assets you're explicitly authorised to test** (your
> own systems, or in-scope bug-bounty / pentest targets). Crawling, API probing,
> and secret scanning generate real traffic. You are responsible for staying in scope.

---

## Contents

| File | What it is |
|------|-----------|
| `bbcrawl.sh` | The main orchestrator — runs the whole pipeline. |
| `jsecret.py` | Secret + endpoint extractor for JS/responses (pure stdlib, ~90 patterns + tuned entropy). Now with **low-noise generic detection**, **clickable source URLs** (`--url-map`), **source-map reconstruction**, and **lazy-chunk discovery** (`--find-chunks`). |
| `apirecon.py` | API-surface recon: Swagger/OpenAPI parser, GraphQL introspection, well-known artifacts, CORS/CSP checks (pure stdlib; YAML optional). |
| `bbreport.py` | Classifies + risk-scores endpoints, builds ffuf wordlists, and renders a self-contained clickable `report.html`. Also does the incremental "what's new" diff. |
| `install.sh` | Installs every dependency (Go tools, python tools, gf patterns; optional `pyyaml`/`jsbeautifier`). |
| `README.md` | This file. |

All three Python tools are **pure standard library** (no required pip installs)
and degrade gracefully if an optional tool or lib is missing.

---

## Quick start

```bash
# 1. install dependencies (Linux apt/dnf/pacman or macOS brew)
./install.sh
source ~/.bashrc            # so $HOME/go/bin is on PATH

# 2. run it
./bbcrawl.sh -d target.com --all
```

Output lands in `recon-target.com-<date>/`. Start with `SUMMARY.txt`, then
`interesting.txt`, `secrets.txt`, and `endpoints_from_js.txt`.

---

## The multi-pass deep crawl

A single `katana -d 3` only reaches depth 3 from your seed hosts. This runs
katana **in passes**, seeding each pass with the previous pass's output:

```
pass 1:  katana -d 2   (seeds: live hosts)         → finds set A
pass 2:  katana -d 3   (seeds: in-scope URLs in A)  → reaches much deeper
```

Control it with `--depths`:

```bash
--depths 2,3       # default: two passes (depth 2, then depth 3)
--depths 2,3,3     # three passes — goes even deeper
--depths 3         # single pass, classic behaviour
```

Two safety rails keep it from wandering off-target or exploding:

* **Scope lock** — seeds for later passes are filtered to your registrable root
  domain(s). It understands compound TLDs (`co.uk`, `com.au`, `co.jp`, …) so it
  won't accidentally scope to a whole public suffix.
* **Seed cap** — `--max-seeds N` (default 2500) limits how many URLs feed a
  deeper pass, so a big pass-1 result doesn't make pass-2 run forever.

`gospider` and `hakrawler` run alongside katana to catch links its parser misses.

---

## What each stage produces

```
recon-<target>-<date>/
├── report.html                # ⭐ open this first — clickable secrets + ranked endpoints
├── SUMMARY.txt                # counts + top secret findings
├── prioritized_endpoints.txt  # every endpoint classified + risk-scored (0-100), highest first
├── endpoints_full.txt         # all known full URLs, deduped (feed ffuf/nuclei)
├── wordlist_paths.txt         # target-specific path wordlist for ffuf
├── wordlist_params.txt        # discovered parameter names for ffuf/arjun
├── subdomains.txt             # from subfinder/assetfinder/crt.sh (--subs)
├── live.txt / live_detailed.txt  # live hosts (+ status/title/tech)
├── all_urls.txt               # every in-scope URL, normalised & deduped
├── endpoints.txt              # real routes only (assets split out below)
├── assets.txt                 # .js/.css/.map/img/font + _next/static chunks (the noise)
├── endpoints_from_js.txt      # endpoints parsed out of JS (jsluice + jsecret)
├── endpoints_src.tsv          # endpoint <TAB> where-it-came-from (clickable source)
├── js.txt                     # every .js URL found
├── params_urls.txt / param_keys.txt   # param URLs / distinct param names
├── interesting.txt            # api/admin/graphql/upload/oauth/.git/.env/…
├── secrets.txt                # LOW-NOISE, CLICKABLE secret findings (medium+); full set in raw/
├── api_endpoints.txt / .json  # OpenAPI/Swagger ops: METHOD [auth|public] url params  (apirecon)
├── graphql_summary.txt        # GraphQL introspection: queries/mutations/subscriptions (apirecon)
├── graphql/<host>.json        # full GraphQL schema per host
├── wellknown.txt / _urls.txt  # robots/sitemap/security.txt/manifest/sw/assetlinks/…
├── cors_csp.txt               # reflected-origin + missing-CSP notes                 (apirecon)
├── sensitive_files.txt        # .git/.env/backup/actuator hits                       (--dirs)
├── nuclei.txt / nuclei_js.txt # nuclei findings                                      (--nuclei)
├── arjun_params.txt           # active hidden params                                 (--arjun)
├── gf/*.txt                   # xss/ssrf/sqli/lfi/redirect/ssti/… hits               (--gf)
├── new_*.txt                  # endpoints/js/secrets/subdomains new since last run   (--incremental)
├── js_files/                  # downloaded JS bodies + url_index.txt + maps/ (reconstructed sources)
├── screenshots/               # gowitness captures                                   (--screens)
├── .bbstate/                  # snapshots powering --incremental
└── raw/                       # unmerged intermediates + JSON (jsecret.json, chunk_urls.txt, …)
```

**secrets.txt is now clickable and low-noise:** each line is
`[sev] Rule | masked-value | https://real-source-url` — the real remote URL the
saved JS came from, not a local file path — so you can click straight through to
re-check. Generic `password`/`apiKey` matches only fire when the value actually
looks like a secret (entropy + character-class + anti-template checks), so the
`passwordExpiry` / `passwordPolicy` style false positives are gone. The full
unfiltered set (including low-severity/entropy hits) stays in `raw/jsecret.json`.

---

## Flags

Run `./bbcrawl.sh -h` for the full list. Highlights:

**Target** `-d DOMAIN` · `-l FILE` · `-o DIR`
**Crawl** `--depths 2,3` · `--max-seeds N` · `-t THREADS` · `--rate N` · `--headless`
**Auth'd crawl** `-H "K: V"` (repeatable) · `--cookie "c=v"` · `--proxy URL` · `-k`
**Scope** `--scope REGEX` · `--exclude REGEX`
**Stages (opt-in)** `--subs --arjun --nuclei --gf --screens --dirs`
**Stages (opt-out)** `--no-api --no-sourcemaps --no-chunks --no-report --no-passive --no-active --no-js --no-secrets --no-params`
**Bulk** `--all` (everything **except nuclei**) · `--passive-only`
**Resume / diff** `--resume` · `--incremental`
**Misc** `--notify WEBHOOK_URL` (Slack/Discord/Telegram) · `--silent`

Default stages (no flags): passive URLs + active deep crawl + JS analysis (incl.
source-map reconstruction + lazy-chunk discovery) + secrets + parameter mining +
API recon + classification/report. `--all` additionally turns on subs, arjun, gf,
screenshots and sensitive-file probing — **but never nuclei**; pass `--nuclei` if
you want it.

### Resume an interrupted run

`--resume` skips any stage whose output already exists, so if you Ctrl-C mid-run
(e.g. during nuclei) you can re-run the *same command* and it flies through the
finished stages in seconds and continues where it stopped — **no re-crawling**. It
still re-runs the cheap local JS analysis over already-saved bodies, so upgrades
(like the secret-noise fix) apply on resume without re-downloading anything. To
finish an interrupted run and also drop nuclei, add `--resume` and don't pass
`--nuclei`.

You can regenerate just the report + wordlists from data already on disk at any
time, without any network traffic:

```bash
python3 bbreport.py -o recon-target-YYYYMMDD/      # writes report.html, prioritized_endpoints.txt, wordlists
```

---

## Recipes

```bash
# Fast pass — URLs, JS, params, secrets only
./bbcrawl.sh -d target.com

# Everything, deeper, more threads
./bbcrawl.sh -d target.com --all --depths 2,3,3 -t 80

# Whole scope from a file, with gf + nuclei but no screenshots
./bbcrawl.sh -l scope.txt --subs --gf --nuclei

# Authenticated crawl of a SPA (headless renders JS), find hidden params
./bbcrawl.sh -d app.target.com --cookie 'session=eyJ...' --headless --arjun

# Route everything through Burp for inspection
./bbcrawl.sh -d target.com --proxy http://127.0.0.1:8080 -k

# Archives only (zero active traffic to the target)
./bbcrawl.sh -d target.com --passive-only

# Narrow scope to one path prefix, drop logout links
./bbcrawl.sh -d target.com --scope '/api/' --exclude 'logout|signout'

# Ping a Slack channel with the summary when done
./bbcrawl.sh -d target.com --all --notify https://hooks.slack.com/services/XXX
```

---

## Using `jsecret.py` on its own

Point it at files, a directory, or remote URLs. Pure standard library — no pip
installs needed.

```bash
# one file
python3 jsecret.py -f app.min.js

# a whole directory of downloaded JS, write JSON, and make findings clickable
# (--url-map takes an httpx -srd index.txt OR a plain "localpath<TAB>url" file)
python3 jsecret.py -d ./js_files --url-map ./js_files/response/index.txt \
        --secrets-out secrets.txt --endpoints-detailed endpoints_src.tsv

# fetch a list of JS URLs concurrently and scan them (only medium+ severity)
cat js_urls.txt | python3 jsecret.py --stdin --fetch --threads 30 --min-severity medium

# only high-severity secrets (good for CI gating)
python3 jsecret.py -d ./js_files --only-secrets --high-only

# discover lazy webpack/Vite/Next chunks referenced by a bundle (prints URLs)
python3 jsecret.py -d ./js_files --find-chunks --base-url https://target.com \
        --chunks-out chunks.txt

# reveal full secret values instead of masking them
python3 jsecret.py -d ./js_files --show-secrets
```

Key flags: `--url-map` (clickable source URLs), `--min-severity high|medium|low`,
`--show-secrets` (no masking), `--endpoints-detailed FILE` (endpoint→source),
`--find-chunks` + `--base-url` + `--chunks-out` (lazy-chunk discovery). `.map`
files it encounters are parsed as **source maps** — original sources are
reconstructed from `sourcesContent` and scanned, so findings are attributed to
the real original filename (e.g. `payments.js:12`), not the minified bundle.

It exits **2** when any high-severity secret is found (handy in pipelines); `0`
otherwise. It detects ~90 provider patterns (AWS, GCP, Azure, Stripe,
GitHub/GitLab, Slack, Twilio, SendGrid, Shopify, database URIs, private keys,
JWTs, …) plus a tuned generic/entropy detector with aggressive false-positive
suppression, and pulls relative/absolute paths, API routes, and dynamically
constructed `fetch`/`axios`/XHR/GraphQL URLs out of JS.

---

## Using `apirecon.py` on its own

Enumerate the API surface of a set of live hosts. Pure stdlib (YAML specs need
the optional `pyyaml`).

```bash
# swagger/openapi + graphql introspection + well-known + cors, over a host list
python3 apirecon.py -l live.txt -o out/

# a single host, only swagger + graphql, through Burp, skipping TLS checks
python3 apirecon.py -u https://api.target.com --only swagger,graphql \
        --proxy http://127.0.0.1:8080 -k
```

Writes `api_endpoints.txt` (METHOD `[auth|public]` url params), `graphql_summary.txt`
+ `graphql/<host>.json`, `wellknown.txt`, and `cors_csp.txt`. `public` API ops
(unauthenticated) and reflected-origin-with-credentials CORS are called out as
attack surface — but they're **candidates**; confirm impact by hand.

---

## Using `bbreport.py` on its own

Turn any bbcrawl output dir into ranked, clickable results — **no network
traffic**, so it's the fastest way to review data you already collected:

```bash
python3 bbreport.py -o recon-target-YYYYMMDD/          # report.html + wordlists + prioritised list
python3 bbreport.py -o recon-target-YYYYMMDD/ --incremental   # also diff vs last run -> new_*.txt
```

It classifies every endpoint (Admin / Payments / Uploads / Auth / GraphQL /
Debug-Infra / UserMgmt / API / Other), risk-scores it 0-100 (with boosts for
SSRF/redirect/LFI params and object-id/IDOR patterns), deprioritises static
assets, and renders `report.html` with clickable secrets and endpoints plus
`wordlist_paths.txt` / `wordlist_params.txt` for ffuf.

---

## Skipped features (and why)

A few items on the "make it the most powerful tool" list were deliberately left
out or handled differently, to avoid heavy dependencies you also asked to avoid
and to keep the pipeline pure-stdlib and modular:

- **Full JavaScript AST engine (in Python)** — a real JS parser is a heavy
  dependency, and **`jsluice`** (already in the pipeline) does tree-sitter-based
  AST parsing of JS. Instead of duplicating that, `jsecret.py` adds targeted
  `fetch()`/`axios()`/XHR/GraphQL call harvesting on top of `jsluice`'s AST layer.
- **Full JavaScript deobfuscator** — general deobfuscation is a research problem
  and error-prone. The installer offers optional **`jsbeautifier`** (pure Python)
  for beautification; for heavier packing, run **`webcrack`** / **`wakaru`**
  externally, then point `jsecret.py -d` at the output.
- **Playwright/Chromium SPA rendering (core)** — a full browser is exactly the
  kind of heavy dependency to avoid; **`katana --headless`** (`--headless` flag)
  already renders JS-heavy SPAs. Source-map reconstruction + recursive chunk
  discovery recover most "dynamic" routes without a browser. A Playwright pass can
  be bolted on as an external step if you ever need it.

Everything else on the list is implemented: source maps, OpenAPI/Swagger, GraphQL
introspection, chunk discovery, tuned secret detection with FP suppression,
endpoint risk scoring/classification, well-known/CORS/CSP parsing, the HTML
report, ffuf wordlists, incremental mode, and resume — all with graceful
fallback when an optional tool is missing, and backward-compatible CLI flags.

---

## Optional features included

* **Subdomain enumeration** (`--subs`) via subfinder + assetfinder + crt.sh, then httpx for live hosts / titles / tech.
* **Passive URL sources** — gau (Wayback + CommonCrawl + OTX + URLScan), waybackurls, katana passive.
* **Active multi-pass crawl** — katana (JS crawl, known files, headless) + gospider + hakrawler.
* **JS pipeline** — download bodies, extract endpoints (jsluice + jsecret), fold them back into the endpoint list.
* **Secret scanning** — jsecret regex/entropy engine + jsluice secrets + trufflehog (verified detectors).
* **Parameter mining** — unfurl keys, paramspider (archives), and optional active **arjun** discovery on high-signal endpoints.
* **`gf` vuln patterns** (`--gf`) — auto-runs xss/ssrf/sqli/lfi/rce/redirect/ssti/idor/interesting-params patterns.
* **Sensitive-file probing** (`--dirs`) — `.git/config`, `.env`, backups, `actuator/*`, swagger/openapi, `security.txt`, etc.
* **nuclei** (`--nuclei`) — exposure / misconfig / takeover / tech / CVE templates on live hosts and JS URLs.
* **Screenshots** (`--screens`) — gowitness captures of every live host.
* **Auth-aware** — custom headers / cookie flow through every downstream tool for crawling behind a login.
* **Proxy + insecure** — send everything through Burp/ZAP; skip TLS checks for dev hosts.
* **Scope control** — registrable-domain lock, plus `--scope` / `--exclude` regexes.
* **Webhook notifications** — Slack / Discord / Telegram summary on completion.
* **Graceful degradation** — missing tools are skipped with a warning; the run never hard-fails on one absent binary.
* **Resumable** — every list appends uniquely (via `anew`/`sort -u`), so re-running enriches instead of overwriting.

---

## Where to look first (bug-bounty workflow)

1. `SUMMARY.txt` — the numbers and the top secret hits.
2. `secrets.txt` — high-severity lines first. **A leaked key isn't a finding until
   you prove what it accesses** — verify before reporting.
3. `interesting.txt` — api/admin/graphql/upload/oauth/import endpoints. These are
   where IDOR, SSRF, auth bypass and mass-assignment live.
4. `endpoints_from_js.txt` — routes the app never links to in the UI; often the
   least-reviewed attack surface.
5. `gf/ssrf.txt`, `gf/redirect.txt`, `gf/sqli.txt`, … — parameter candidates to
   probe by hand.
6. `params_urls.txt` + `arjun_params.txt` — feed these into your own fuzzers
   (`ffuf`, `qsreplace`, `dalfox`).

This is a discovery layer. It finds surface fast; **you still verify impact by
hand** — automated hits are candidates, not confirmed bugs.

---

## Extending

* **More secret patterns** — add a `(name, regex, severity)` tuple to
  `_RAW_PATTERNS` in `jsecret.py`.
* **More gf patterns** — drop `.json` pattern files into `~/.gf/` (the installer
  seeds it from tomnomnom's and 1ndianl33t's packs).
* **More sensitive paths** — edit the `SENS=` list in the STAGE 10 block of
  `bbcrawl.sh`.
* **Different crawl behaviour** — tweak `KFLAGS`/`GS`/`HK` (katana / gospider /
  hakrawler flag arrays) near the top of the script.

---

## Dependencies

Installed by `install.sh`: **go**, subfinder, httpx, katana, nuclei, dnsx, gau,
waybackurls, assetfinder, gf (+patterns), qsreplace, anew, unfurl, uro,
hakrawler, gospider, jsluice, subzy, gowitness, paramspider, arjun, trufflehog.

`jsecret.py` needs only Python 3.8+ (standard library). Everything else is
optional — bbcrawl uses what's present and skips the rest.
