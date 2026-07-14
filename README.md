# bbcrawl — all-in-one deep crawler & recon for bug bounty

Crawl a target as deeply as possible and pull out everything worth looking at:
**endpoints, JS files, endpoints hidden inside JS, parameters, and secrets** —
plus optional nuclei scanning, `gf` vuln-pattern extraction, sensitive-file
probing, and screenshots. It wraps the standard recon toolchain and adds a
**multi-pass "deep katana" crawl** (the `katana -d 2` → feed output → `katana -d 3`
idea) so later passes treat earlier discoveries as fresh roots and reach much
deeper than a single crawl.

> ⚠️ **Only run this against assets you're explicitly authorised to test** (your
> own systems, or in-scope bug-bounty / pentest targets). Crawling and secret
> scanning generate real traffic. You are responsible for staying in scope.

---

## Contents

| File | What it is |
|------|-----------|
| `bbcrawl.sh` | The main orchestrator — runs the whole pipeline. |
| `jsecret.py` | Standalone secret + endpoint extractor for JS/responses (pure stdlib, ~90 patterns + entropy). Used by `bbcrawl.sh` and usable on its own. |
| `install.sh` | Installs every dependency (Go tools, python tools, gf patterns). |
| `README.md` | This file. |

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
├── SUMMARY.txt                 # counts + top secret findings (read this first)
├── subdomains.txt              # from subfinder/assetfinder/crt.sh (--subs)
├── live.txt                    # live hosts (httpx)
├── live_detailed.txt           # host + status + title + tech
├── all_urls.txt                # every in-scope URL, normalised & deduped
├── endpoints.txt               # all paths (+ endpoints recovered from JS)
├── endpoints_from_js.txt       # endpoints parsed out of JS (jsluice + jsecret)
├── js.txt                      # every .js URL found
├── params_urls.txt             # URLs carrying query parameters
├── param_keys.txt              # distinct parameter names seen
├── interesting.txt             # api/admin/graphql/upload/oauth/.git/.env/…
├── subdomains_from_crawl.txt   # new subdomains the crawl surfaced
├── secrets.txt                 # merged secret findings (jsecret+jsluice+trufflehog)
├── sensitive_files.txt         # .git/.env/backup/actuator hits          (--dirs)
├── nuclei.txt / nuclei_js.txt  # nuclei findings                         (--nuclei)
├── arjun_params.txt            # active hidden params                    (--arjun)
├── gf/*.txt                    # xss/ssrf/sqli/lfi/redirect/ssti/… hits  (--gf)
├── js_files/                   # downloaded JS bodies
├── screenshots/                # gowitness captures                      (--screens)
└── raw/                        # unmerged intermediates + JSON (jsecret.json, etc.)
```

---

## Flags

Run `./bbcrawl.sh -h` for the full list. Highlights:

**Target** `-d DOMAIN` · `-l FILE` · `-o DIR`
**Crawl** `--depths 2,3` · `--max-seeds N` · `-t THREADS` · `--rate N` · `--headless`
**Auth'd crawl** `-H "K: V"` (repeatable) · `--cookie "c=v"` · `--proxy URL` · `-k`
**Scope** `--scope REGEX` · `--exclude REGEX`
**Stages** `--subs --arjun --nuclei --gf --screens --dirs` · toggles `--no-passive --no-active --no-js --no-secrets --no-params` · `--all` · `--passive-only`
**Misc** `--notify WEBHOOK_URL` (Slack/Discord/Telegram) · `--silent`

Default stages (no flags): passive URLs + active deep crawl + JS analysis +
secrets + parameter mining. `--all` turns on everything including subs, nuclei,
gf, screenshots and sensitive-file probing.

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

# a whole directory of downloaded JS, write JSON
python3 jsecret.py -d ./js_files --json findings.json

# fetch a list of JS URLs concurrently and scan them
cat js_urls.txt | python3 jsecret.py --stdin --fetch --threads 30

# only high-severity secrets (good for CI gating)
python3 jsecret.py -d ./js_files --only-secrets --high-only
```

It exits **2** when any high-severity secret is found (handy in pipelines);
`0` otherwise. Findings are redacted in the terminal; full context is in the JSON.

It detects ~90 provider patterns (AWS, GCP, Azure, Stripe, GitHub/GitLab, Slack,
Twilio, SendGrid, Shopify, database URIs, private keys, JWTs, …) plus a generic
high-entropy detector that only fires near secret-y keywords to keep noise down,
and it pulls relative/absolute paths, API routes, and URLs out of JS.

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
