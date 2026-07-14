#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jsecret.py  -  JS/response secret + endpoint extractor for bug bounty recon.

Pure standard library (no pip installs needed). Works on:
  - local .js / .json / .html / .txt files
  - directories (recurses; .map files are parsed as source maps)
  - remote URLs (fetched concurrently)
  - stdin (a list of file paths or URLs, one per line)

It does several jobs:
  1. SECRETS   - ~90 curated provider patterns + tuned generic/entropy detection
                 with aggressive false-positive suppression (low noise).
  2. ENDPOINTS - pulls relative/absolute paths, API routes and URLs out of JS,
                 and records the SOURCE each endpoint came from.
  3. SOURCEMAPS- reconstructs original sources from .map files (sourcesContent)
                 and scans those too -> real filenames, real routes, real secrets.
  4. CHUNKS    - (--find-chunks) discovers lazy-loaded webpack/Vite/Next chunks
                 so the caller can download and scan them recursively.

Clickable output: pass --url-map (an httpx -srd index.txt, or a plain
"localpath<TAB>url" file) and findings are reported against the real remote URL
instead of the local saved file, so you can click straight through to re-check.

Examples:
  python3 jsecret.py -f app.js
  python3 jsecret.py -d ./js_files --url-map ./js_files/response/index.txt \\
          --secrets-out secrets.txt --endpoints-detailed endpoints_src.tsv
  python3 jsecret.py -d ./js_files --find-chunks --base-url https://t.com
  cat js_urls.txt | python3 jsecret.py --stdin --fetch --threads 30 --min-severity medium
"""

import argparse
import concurrent.futures as cf
import json
import math
import os
import re
import sys
import urllib.request
import urllib.parse
import ssl
from collections import defaultdict

# --------------------------------------------------------------------------- #
#  Terminal colors                                                            #
# --------------------------------------------------------------------------- #
class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    M = "\033[95m"; CY = "\033[96m"; W = "\033[97m"; GR = "\033[90m"
    BOLD = "\033[1m"; END = "\033[0m"

    @staticmethod
    def strip():
        for k in ("R", "G", "Y", "B", "M", "CY", "W", "GR", "BOLD", "END"):
            setattr(C, k, "")


# --------------------------------------------------------------------------- #
#  Secret patterns   (name, regex, severity)                                  #
#  Severity: high = live credential likely, medium = sensitive, low = info    #
#  "generic" flag => value must pass the strict secret-value test below.      #
# --------------------------------------------------------------------------- #
_RAW_PATTERNS = [
    # ---- Cloud providers ------------------------------------------------- #
    ("AWS Access Key ID",        r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b", "high", False),
    ("AWS Secret Access Key",    r"(?i)aws(.{0,20})?(?:secret|sk)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]", "high", False),
    ("AWS MWS Auth Token",       r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "high", False),
    ("AWS Session Token",        r"(?i)aws_session_token['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{100,}['\"]", "high", False),
    ("Google API Key",           r"\bAIza[0-9A-Za-z\-_]{35}\b", "high", False),
    ("Google OAuth Client ID",   r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", "low", False),
    ("Google OAuth Secret",      r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b", "high", False),
    ("GCP Service Account",      r"\"type\":\s*\"service_account\"", "high", False),
    ("Firebase URL",             r"https://[a-z0-9.-]+\.firebaseio\.com", "low", False),
    ("Firebase Cloud Msg Key",   r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b", "high", False),
    ("Azure Storage Key",        r"(?i)AccountKey=[A-Za-z0-9+/=]{88}", "high", False),
    ("Azure Connection String",  r"(?i)DefaultEndpointsProtocol=https?;AccountName=", "high", False),
    ("Azure AD Client Secret",   r"(?i)client_secret['\"]?\s*[:=]\s*['\"][0-9A-Za-z\-_.~]{34,40}['\"]", "high", False),
    ("DigitalOcean Token",       r"\bdop_v1_[a-f0-9]{64}\b", "high", False),
    ("DigitalOcean OAuth",       r"\bdoo_v1_[a-f0-9]{64}\b", "high", False),
    ("Heroku API Key",           r"(?i)heroku(.{0,20})?['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]", "high", False),

    # ---- Version control / CI -------------------------------------------- #
    ("GitHub PAT (classic)",     r"\bghp_[0-9A-Za-z]{36}\b", "high", False),
    ("GitHub Fine-grained PAT",  r"\bgithub_pat_[0-9A-Za-z_]{82}\b", "high", False),
    ("GitHub OAuth Token",       r"\bgho_[0-9A-Za-z]{36}\b", "high", False),
    ("GitHub App Token",         r"\b(?:ghu|ghs)_[0-9A-Za-z]{36}\b", "high", False),
    ("GitHub Refresh Token",     r"\bghr_[0-9A-Za-z]{36}\b", "high", False),
    ("GitLab PAT",               r"\bglpat-[0-9A-Za-z\-_]{20}\b", "high", False),
    ("GitLab Pipeline Token",    r"\bglptt-[0-9a-f]{40}\b", "high", False),
    ("NPM Access Token",         r"\bnpm_[0-9A-Za-z]{36}\b", "high", False),
    ("PyPI Upload Token",        r"\bpypi-AgEIcHlwaS[0-9A-Za-z\-_]{50,}\b", "high", False),
    ("Docker Hub PAT",           r"\bdckr_pat_[0-9A-Za-z\-_]{27,}\b", "high", False),

    # ---- Payments -------------------------------------------------------- #
    ("Stripe Live Secret Key",   r"\bsk_live_[0-9a-zA-Z]{24,}\b", "high", False),
    ("Stripe Live Restricted",   r"\brk_live_[0-9a-zA-Z]{24,}\b", "high", False),
    ("Stripe Test Secret Key",   r"\bsk_test_[0-9a-zA-Z]{24,}\b", "medium", False),
    ("Stripe Publishable Key",   r"\bpk_live_[0-9a-zA-Z]{24,}\b", "low", False),
    ("Square Access Token",      r"\bsq0atp-[0-9A-Za-z\-_]{22}\b", "high", False),
    ("Square OAuth Secret",      r"\bsq0csp-[0-9A-Za-z\-_]{43}\b", "high", False),
    ("PayPal Braintree Token",   r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b", "high", False),
    ("Razorpay Key",             r"\brzp_(?:live|test)_[0-9A-Za-z]{14}\b", "medium", False),

    # ---- Comms / email / SMS --------------------------------------------- #
    ("Slack Token",              r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b", "high", False),
    ("Slack Webhook",            r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,}/B[0-9A-Za-z_]{8,}/[0-9A-Za-z_]{24}", "high", False),
    ("Discord Bot Token",        r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b", "high", False),
    ("Discord Webhook",          r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z_-]{60,68}", "medium", False),
    ("Telegram Bot Token",       r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b", "high", False),
    ("Twilio API Key",           r"\bSK[0-9a-fA-F]{32}\b", "high", False),
    ("Twilio Account SID",       r"\bAC[0-9a-fA-F]{32}\b", "medium", False),
    ("SendGrid API Key",         r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b", "high", False),
    ("Mailgun API Key",          r"\bkey-[0-9a-zA-Z]{32}\b", "high", False),
    ("Mailchimp API Key",        r"\b[0-9a-f]{32}-us[0-9]{1,2}\b", "high", False),
    ("Postmark Server Token",    r"(?i)postmark(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "high", False),
    ("Nexmo/Vonage API Secret",  r"(?i)nexmo(.{0,20})?['\"][0-9a-zA-Z]{16}['\"]", "high", False),

    # ---- SaaS / infra ---------------------------------------------------- #
    ("Datadog API Key",          r"(?i)datadog(.{0,20})?['\"][0-9a-f]{32}['\"]", "high", False),
    ("New Relic License",        r"\bNRAK-[0-9A-Z]{27}\b", "high", False),
    ("New Relic Insights Key",   r"\bNRJS-[0-9a-f]{19}\b", "medium", False),
    ("PagerDuty Token",          r"\b[0-9a-z]{20}@pdt\b", "high", False),
    ("Cloudflare API Token",     r"(?i)cloudflare(.{0,20})?['\"][A-Za-z0-9_-]{40}['\"]", "high", False),
    ("Cloudflare Global Key",    r"(?i)x-auth-key['\"]?\s*[:=]\s*['\"][0-9a-f]{37}['\"]", "high", False),
    ("Algolia Admin Key",        r"(?i)algolia(.{0,20})?(?:admin|api)(.{0,20})?['\"][0-9a-f]{32}['\"]", "high", False),
    ("Contentful Token",         r"(?i)contentful(.{0,20})?['\"][0-9A-Za-z\-_]{43}['\"]", "medium", False),
    ("Sentry DSN",               r"https://[0-9a-f]{32}@[0-9a-z.-]+/[0-9]+", "medium", False),
    ("Segment Write Key",        r"(?i)segment(.{0,20})?(?:write_key|writeKey)(.{0,20})?['\"][0-9A-Za-z]{32}['\"]", "medium", False),
    ("Airtable PAT",             r"\bpat[0-9A-Za-z]{14}\.[0-9a-f]{64}\b", "high", False),
    ("Shopify Access Token",     r"\bshpat_[0-9a-fA-F]{32}\b", "high", False),
    ("Shopify Custom App Token", r"\bshpca_[0-9a-fA-F]{32}\b", "high", False),
    ("Shopify Shared Secret",    r"\bshpss_[0-9a-fA-F]{32}\b", "high", False),
    ("Shopify Private App",      r"\bshppa_[0-9a-fA-F]{32}\b", "high", False),
    ("Linear API Key",           r"\blin_api_[0-9A-Za-z]{40}\b", "high", False),
    ("Notion Integration Token", r"\bsecret_[0-9A-Za-z]{43}\b", "high", False),
    ("Atlassian API Token",      r"\bATATT3[0-9A-Za-z_\-]{180,}\b", "high", False),
    ("Dropbox Token",            r"\bsl\.[0-9A-Za-z_-]{130,152}\b", "high", False),
    ("Okta API Token",           r"(?i)okta(.{0,20})?['\"]00[0-9A-Za-z_-]{40}['\"]", "high", False),
    ("Hubspot API Key",          r"(?i)hubspot(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "high", False),
    ("Intercom Access Token",    r"(?i)intercom(.{0,20})?['\"]dG9r[0-9A-Za-z=_-]{20,}['\"]", "high", False),

    # ---- Databases ------------------------------------------------------- #
    ("Postgres URI",             r"postgres(?:ql)?://[^\s:@/]+:[^\s:@/]+@[^\s/'\"]+", "high", False),
    ("MySQL URI",                r"mysql://[^\s:@/]+:[^\s:@/]+@[^\s/'\"]+", "high", False),
    ("MongoDB URI",              r"mongodb(?:\+srv)?://[^\s:@/]+:[^\s:@/]+@[^\s/'\"]+", "high", False),
    ("Redis URI",                r"redis://[^\s:@/]*:[^\s:@/]+@[^\s/'\"]+", "high", False),
    ("JDBC Connection",          r"jdbc:[a-z]+://[^\s;'\"]+;?(?:user|password)=", "high", False),

    # ---- Generic keys / auth --------------------------------------------- #
    ("JWT",                      r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b", "medium", False),
    ("Basic Auth in URL",        r"[a-zA-Z][a-zA-Z0-9+.\-]{1,9}://[^/\s:@'\"]{3,30}:[^/\s:@'\"]{3,30}@[a-z0-9.\-]+", "high", False),
    ("Private Key Block",        r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)? ?PRIVATE KEY(?: BLOCK)?-----", "high", False),
    ("PuTTY Private Key",        r"PuTTY-User-Key-File-[23]:", "high", False),
    # generic assignments (value must pass strict test) --------------------- #
    ("Generic API Key assign",   r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|private[_-]?key|encryption[_-]?key)['\"]?\s*[:=]\s*['\"]([^'\"\s]{12,120})['\"]", "medium", True),
    ("Generic Secret assign",    r"(?i)(?<![a-z])(?:password|passwd|pwd|db[_-]?pass|secret|token)['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,120})['\"]", "medium", True),
]

PATTERNS = [(name, re.compile(rx), sev, generic) for name, rx, sev, generic in _RAW_PATTERNS]

# --------------------------------------------------------------------------- #
#  False-positive suppression for GENERIC/entropy matches                     #
# --------------------------------------------------------------------------- #
# Whole-value shapes that are never real secrets.
_FP_EXACT = re.compile(
    r"(?i)^(?:"
    r"x{3,}|0{4,}|1234567890\d*|abcdef0123\w*|deadbeef|null|undefined|none|nil|"
    r"true|false|test|testing|example|examples|sample|demo|dummy|foobar|foo|bar|baz|"
    r"your[_-]?\w*|my[_-]?\w*|changeme|placeholder|redacted|hidden|secret|password|"
    r"enter[_-]?\w*|type[_-]?\w*|string|number|boolean|object|array|value|default|"
    r"unknown|invalid|disabled|enabled|required|optional|primary|secondary"
    r")$"
)
# Substrings that mean "this is UI/i18n/template text, not a secret".
_FP_CONTAINS = re.compile(
    r"(?:\$\{|\{\{|<%|%\(|#\{|%s\b|%d\b|\}\}|/>|</|::|"          # templating / markup
    r"lorem ipsum|\.(?:png|jpe?g|svg|gif|css|js|woff|ttf|html)|"  # asset-ish literals
    r"@[a-z0-9.-]+\.[a-z]{2,}$)"                                  # bare email addr
)
# Values that are really i18n keys / dotted identifiers / css.
_FP_IDENTIFIER = re.compile(r"^(?:[a-z0-9]+[._-]){2,}[a-z0-9]+$", re.I)   # a.b.c / a_b_c_d
_HEX_ONLY      = re.compile(r"^[0-9a-f]+$", re.I)
_ALNUM_WORD    = re.compile(r"^[a-z]+$", re.I)                             # a single word


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for ch in data:
        freq[ch] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def looks_like_real_secret(val: str, min_entropy: float) -> bool:
    """Strict gate for GENERIC / entropy findings to keep noise down."""
    v = val.strip().strip("'\"`")
    n = len(v)
    if n < 8 or n > 200:
        return False
    if _FP_EXACT.match(v):
        return False
    if _FP_CONTAINS.search(v):
        return False
    if _ALNUM_WORD.match(v):                 # a plain word ("Password", "expiryDate")
        return False
    if _FP_IDENTIFIER.match(v) and shannon_entropy(v) < 3.6:
        return False                          # dotted/snake i18n key
    # must mix character classes -> real keys/passwords do
    classes = sum(bool(re.search(p, v)) for p in
                  (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    if classes < 2:
        return False
    # short hex (< 24) is usually a colour/id, not a secret
    if _HEX_ONLY.match(v) and n < 24:
        return False
    if shannon_entropy(v) < min_entropy:
        return False
    return True


# --------------------------------------------------------------------------- #
#  Endpoint extraction (LinkFinder-derived regex, MIT)                        #
# --------------------------------------------------------------------------- #
ENDPOINT_RE = re.compile(r"""
  (?:"|'|`)
  (
    ((?:[a-zA-Z]{1,10}://|//)
      [^"'`/]{1,}\.[a-zA-Z]{2,}[^"'`]{0,})
    |
    ((?:/|\.\./|\./)
      [^"'`><,;| *()(%$^/\\\[\]][^"'`><,;|()]{1,})
    |
    ([a-zA-Z0-9_\-/]{1,}/
      [a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)
      (?:[\?|#][^"|'`]{0,}|))
    |
    ([a-zA-Z0-9_\-/]{1,}/
      [a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|'`]{0,}|))
    |
    ([a-zA-Z0-9_\-]{1,}
      \.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)
      (?:[\?|#][^"|'`]{0,}|))
  )
  (?:"|'|`)
""", re.VERBOSE)

# Extra dynamic-call harvesting (fetch/axios/xhr/graphql clients).
CALL_RE = re.compile(r"""
  (?:fetch|axios(?:\.(?:get|post|put|delete|patch|request))?|\.open|
     \.ajax|http\.(?:get|post|put|delete|patch)|useSWR|useQuery|request)
  \s*\(\s*(?:\{[^}]*?url\s*:\s*)?
  (?:"|'|`)([^"'`]{2,200})(?:"|'|`)
""", re.VERBOSE)

ENDPOINT_REJECT = re.compile(
    r"(?i)\.(?:png|jpe?g|gif|svg|ico|woff2?|ttf|eot|css|mp4|webp|webm|"
    r"avif|bmp|mp3|wav)(?:$|[?#])|^(?:text/|image/|application/|application$|"
    r"[0-9.]+$|https?://(?:www\.)?w3\.org|use strict|charset)"
)

SECRETY_KEYWORDS = re.compile(r"(?i)(secret|token|apikey|api_key|passwd|password|auth|credential|private|access_key)")
_KEYLIKE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def _looks_like_leaked_key(ep: str) -> bool:
    if ep.startswith(("/", "./", "../")) or "://" in ep or "." in ep:
        return False
    if not _KEYLIKE.match(ep):
        return False
    if len(ep) >= 20 and shannon_entropy(ep) > 4.0:
        return True
    return False


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def mask_url_creds(u: str) -> str:
    """scheme://user:pass@host  ->  scheme://user:***@host  (keep the finding useful)."""
    m = re.match(r"([a-zA-Z][\w+.\-]*://)([^:@/]+):([^@/]+)@(.+)", u)
    if not m:
        return u
    return f"{m.group(1)}{m.group(2)}:***@{m.group(4)}"


def render_match(rule: str, raw: str, val: str, show: bool) -> str:
    raw = raw.strip()
    if show:
        return val if val else raw
    if "URI" in rule or "Basic Auth in URL" in rule:
        return mask_url_creds(raw)
    v = (val or raw).strip("'\"` ")
    if len(v) <= 10:
        return v[:3] + "…" + f" (len {len(v)})"
    return f"{v[:4]}…{v[-4:]} (len {len(v)})"


# --------------------------------------------------------------------------- #
#  Secret scanning                                                            #
# --------------------------------------------------------------------------- #
def scan_secrets(source, text, entropy_min, high_only, show):
    out = []
    seen = set()
    for name, rx, sev, generic in PATTERNS:
        if high_only and sev != "high":
            continue
        for m in rx.finditer(text):
            raw = m.group(0)
            # captured value = group(1) if present else the quoted tail
            if m.groups():
                val = m.group(1) or ""
            else:
                val = ""
            if not val:
                vm = re.search(r"['\"`]([^'\"`]{6,})['\"`]\s*$", raw)
                val = vm.group(1) if vm else raw
            if generic and not looks_like_real_secret(val, max(3.0, entropy_min - 0.3)):
                continue
            dedup = (name, val or raw)
            if dedup in seen:
                continue
            seen.add(dedup)
            out.append({
                "type": "secret", "rule": name, "severity": sev,
                "value": (val or raw)[:200],
                "match": render_match(name, raw, val, show),
                "source": source, "line": line_of(text, m.start()),
            })

    # generic high-entropy hunt near a secret-y keyword
    for m in re.finditer(r"['\"`]([A-Za-z0-9\-_+/=]{20,80})['\"`]", text):
        token = m.group(1)
        if any(token == v for (_, v) in seen):
            continue
        window = text[max(0, m.start() - 40): m.start()]
        if not SECRETY_KEYWORDS.search(window):
            continue
        if not looks_like_real_secret(token, entropy_min):
            continue
        dedup = ("High-Entropy String", token)
        if dedup in seen:
            continue
        seen.add(dedup)
        out.append({
            "type": "secret", "rule": "High-Entropy String", "severity": "low",
            "entropy": round(shannon_entropy(token), 2),
            "value": token[:200],
            "match": render_match("High-Entropy String", token, token, show),
            "source": source, "line": line_of(text, m.start()),
        })
    return out


def scan_endpoints(source, text):
    endpoints = {}
    def add(ep):
        ep = ep.strip()
        if len(ep) < 3 or len(ep) > 400:
            return
        if ENDPOINT_REJECT.search(ep):
            return
        if _looks_like_leaked_key(ep):
            return
        # drop concat fragments like "static/chunks/" (not rooted, trailing slash)
        if ep.endswith("/") and not ep.startswith(("/", "./", "../")) and "://" not in ep:
            return
        endpoints.setdefault(ep, source)
    for m in ENDPOINT_RE.finditer(text):
        if m.group(1):
            add(m.group(1))
    for m in CALL_RE.finditer(text):
        add(m.group(1))
    return [{"type": "endpoint", "value": e, "source": s} for e, s in endpoints.items()]


# --------------------------------------------------------------------------- #
#  Source maps: reconstruct original sources from .map (sourcesContent)       #
# --------------------------------------------------------------------------- #
def parse_sourcemap(path_or_text, is_text=False):
    """Return list of (virtual_name, content) reconstructed from a source map."""
    try:
        raw = path_or_text if is_text else open(path_or_text, "r", encoding="utf-8", errors="replace").read()
        data = json.loads(raw)
    except Exception:
        return []
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    out = []
    for i, name in enumerate(sources):
        if i < len(contents) and contents[i]:
            clean = re.sub(r"^(?:\.\./)+", "", str(name)).lstrip("/")
            clean = clean.replace("webpack://", "").replace("://", "/")
            out.append((clean or f"source_{i}", contents[i]))
    return out


# --------------------------------------------------------------------------- #
#  Lazy-chunk discovery (webpack / Vite / Next.js)                            #
# --------------------------------------------------------------------------- #
_CHUNK_FILE = re.compile(r"""['"]([\w./\-]*?static/chunks/[\w./\-]+?\.js)['"]""")
_CHUNK_MAPKV = re.compile(r"""[\{,]\s*(\d+)\s*:\s*["']([0-9a-f]{6,})["']""")
_JS_BARE = re.compile(r"""["']([\w\-]+\.[0-9a-f]{6,}\.(?:js|mjs))["']""")


def discover_chunks(text, base_url):
    """Best-effort list of absolute chunk URLs referenced by a bundle."""
    found = set()
    base = base_url.rstrip("/") if base_url else ""
    origin = ""
    if base:
        p = urllib.parse.urlparse(base)
        origin = f"{p.scheme}://{p.netloc}"
    for m in _CHUNK_FILE.finditer(text):
        rel = m.group(1)
        found.add(_join(origin, base, rel))
    for m in _JS_BARE.finditer(text):
        rel = m.group(1)
        found.add(_join(origin, base, rel))
    return {u for u in found if u}


def _join(origin, base, rel):
    if rel.startswith(("http://", "https://")):
        return rel
    if rel.startswith("/") and origin:
        return _collapse_dupes(origin + rel)
    if base:
        return _collapse_dupes(base.rsplit("/", 1)[0] + "/" + rel.lstrip("./"))
    return ""


def _collapse_dupes(url):
    """Collapse consecutive duplicate path segments (e.g. /static/static/ -> /static/)
    that arise from resolving webpack-relative chunk paths. Candidates are validated
    by httpx downstream, so an occasional over-collapse just 404s harmlessly."""
    try:
        p = urllib.parse.urlparse(url)
        segs = p.path.split("/")
        out = []
        for s in segs:
            if out and s and out[-1] == s:
                continue
            out.append(s)
        return urllib.parse.urlunparse(p._replace(path="/".join(out)))
    except Exception:
        return url


# --------------------------------------------------------------------------- #
#  url-map (clickable source URLs) parsing                                     #
# --------------------------------------------------------------------------- #
def load_url_map(path):
    """
    Accepts:
      - httpx -srd index.txt lines (path and url tokens in any order)
      - plain "localpath<TAB>url" or "localpath url" lines
    Returns dict with several keys per file (full path, abspath, basename,
    host/basename) all mapping to the source URL.
    """
    m = {}
    if not path or not os.path.isfile(path):
        return m
    try:
        for line in open(path, "r", encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            urls = re.findall(r"https?://[^\s\"'()]+", line)
            if not urls:
                continue
            url = urls[0]
            # the path token = a whitespace field that is not the url
            toks = line.split()
            pth = None
            for t in toks:
                if t == url or t.startswith("http"):
                    continue
                if "/" in t or t.endswith(".txt") or t.endswith(".js"):
                    pth = t.strip("\"'")
                    break
            if not pth:
                continue
            _register_path(m, pth, url)
    except Exception:
        pass
    return m


def _register_path(m, pth, url):
    keys = {pth, os.path.abspath(pth), os.path.basename(pth)}
    parent = os.path.basename(os.path.dirname(pth))
    if parent:
        keys.add(f"{parent}/{os.path.basename(pth)}")
    for k in keys:
        m.setdefault(k, url)


def resolve_source(source, url_map):
    if not url_map:
        return None
    for k in (source, os.path.abspath(source), os.path.basename(source),
              f"{os.path.basename(os.path.dirname(source))}/{os.path.basename(source)}"):
        if k in url_map:
            return url_map[k]
    return None


# --------------------------------------------------------------------------- #
#  Input handling                                                             #
# --------------------------------------------------------------------------- #
def fetch(url, timeout, insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (bbcrawl jsecret)"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read(8 * 1024 * 1024).decode("utf-8", "replace")


def read_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(16 * 1024 * 1024)
    except Exception:
        return None


def gather_inputs(args):
    items = []   # (label, kind)  kind in {"file","url","map"}
    if args.file:
        items += [(f, "map" if f.lower().endswith(".map") else "file") for f in args.file]
    if args.dir:
        exts = (".js", ".mjs", ".json", ".html", ".htm", ".txt", ".xml")
        for root, _, files in os.walk(args.dir):
            for fn in files:
                low = fn.lower()
                if low.endswith(".map"):
                    items.append((os.path.join(root, fn), "map"))
                elif low.endswith(exts):
                    items.append((os.path.join(root, fn), "file"))
    if args.url:
        items += [(u, "url") for u in args.url]
    if args.stdin:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            if line.startswith(("http://", "https://")):
                items.append((line, "url"))
            elif line.lower().endswith(".map"):
                items.append((line, "map"))
            else:
                items.append((line, "file"))
    return items


# --------------------------------------------------------------------------- #
#  Driver                                                                      #
# --------------------------------------------------------------------------- #
def process(label, kind, args):
    findings = []
    try:
        if kind == "url":
            text = fetch(label, args.timeout, args.insecure)
        else:
            text = read_file(label)
        if text is None:
            return label, [], [], "read error"
    except Exception as e:
        return label, [], [], f"fetch error: {e}"

    chunk_urls = []
    if args.find_chunks:
        chunk_urls = list(discover_chunks(text, args.base_url or (label if kind == "url" else "")))

    if kind == "map":
        # reconstruct and scan each original source
        for vname, content in parse_sourcemap(text, is_text=True):
            src = f"{label} :: {vname}"
            if not args.only_endpoints:
                findings += scan_secrets(src, content, args.entropy, args.high_only, args.show_secrets)
            if not args.only_secrets:
                findings += scan_endpoints(src, content)
        return label, findings, chunk_urls, None

    if not args.only_endpoints:
        findings += scan_secrets(label, text, args.entropy, args.high_only, args.show_secrets)
    if not args.only_secrets:
        findings += scan_endpoints(label, text)
    return label, findings, chunk_urls, None


SEV_RANK = {"high": 0, "medium": 1, "low": 2}


def sev_at_least(sev, floor):
    return SEV_RANK.get(sev, 3) <= SEV_RANK.get(floor, 2)


def main():
    ap = argparse.ArgumentParser(
        description="Extract secrets + endpoints from JS / responses (stdlib only).",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    s = ap.add_argument_group("inputs")
    s.add_argument("-f", "--file", nargs="+", help="one or more local files")
    s.add_argument("-d", "--dir", help="directory to recurse (.map parsed as source maps)")
    s.add_argument("-u", "--url", nargs="+", help="remote URL(s) to fetch")
    s.add_argument("--stdin", action="store_true", help="read paths/URLs from stdin")
    s.add_argument("--fetch", action="store_true", help="(compat) treat stdin http lines as URLs")

    f = ap.add_argument_group("filters")
    f.add_argument("--only-secrets", action="store_true")
    f.add_argument("--only-endpoints", action="store_true")
    f.add_argument("--high-only", action="store_true", help="only high-severity secret rules")
    f.add_argument("--min-severity", choices=["high", "medium", "low"], default="low",
                   help="drop findings below this severity in output (default low=all)")
    f.add_argument("--entropy", type=float, default=3.8, help="min entropy for generic tokens (default 3.8)")

    c = ap.add_argument_group("chunks / maps")
    c.add_argument("--find-chunks", action="store_true", help="print discovered lazy chunk URLs and exit-list")
    c.add_argument("--base-url", help="base URL used to absolutise discovered chunk paths")
    c.add_argument("--chunks-out", help="write discovered chunk URLs here (one per line)")

    n = ap.add_argument_group("network")
    n.add_argument("-t", "--threads", type=int, default=20)
    n.add_argument("--timeout", type=int, default=15)
    n.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")

    o = ap.add_argument_group("output")
    o.add_argument("--json", help="write JSON results to this path")
    o.add_argument("--endpoints-out", help="append discovered endpoints (one per line)")
    o.add_argument("--endpoints-detailed", help="append 'endpoint<TAB>source' rows")
    o.add_argument("--secrets-out", help="append secret findings (one per line)")
    o.add_argument("--url-map", help="httpx index.txt or 'localpath<TAB>url' to make sources clickable")
    o.add_argument("--show-secrets", action="store_true", help="print full secret values (no redaction)")
    o.add_argument("--no-color", action="store_true")
    o.add_argument("-q", "--quiet", action="store_true", help="only print secrets to terminal")

    args = ap.parse_args()
    if args.no_color or not sys.stdout.isatty():
        C.strip()

    items = gather_inputs(args)
    if not items:
        ap.print_help()
        sys.exit(1)

    url_map = load_url_map(args.url_map)

    all_findings, chunk_urls, errors = [], set(), []
    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futs = [ex.submit(process, lbl, kind, args) for lbl, kind in items]
        for fut in cf.as_completed(futs):
            label, findings, chunks, err = fut.result()
            if err:
                errors.append((label, err)); continue
            all_findings.extend(findings)
            chunk_urls.update(chunks)

    # attach clickable source URLs
    for fnd in all_findings:
        su = resolve_source(fnd["source"], url_map)
        if su:
            # keep any "  :: original.js" suffix from source maps
            suffix = ""
            if " :: " in fnd["source"]:
                suffix = " :: " + fnd["source"].split(" :: ", 1)[1]
            fnd["source_url"] = su + suffix

    # ----- chunk discovery mode ----------------------------------------- #
    if args.find_chunks:
        chunks = sorted(chunk_urls)
        if args.chunks_out:
            with open(args.chunks_out, "w") as fh:
                fh.write("\n".join(chunks) + ("\n" if chunks else ""))
        for u in chunks:
            print(u)
        if not args.json and not args.secrets_out and not args.endpoints_out:
            return

    secrets = [f for f in all_findings if f["type"] == "secret"
               and sev_at_least(f["severity"], args.min_severity)]
    endpoints = [f for f in all_findings if f["type"] == "endpoint"]

    # de-dupe
    uep, seen = [], set()
    for e in endpoints:
        if e["value"] not in seen:
            seen.add(e["value"]); uep.append(e)
    endpoints = uep

    us, seens = [], set()
    for x in secrets:
        key = (x["rule"], x.get("value"), x.get("source_url") or x["source"])
        if key not in seens:
            seens.add(key); us.append(x)
    secrets = us
    secrets.sort(key=lambda x: (SEV_RANK.get(x["severity"], 3), x["rule"]))

    def loc(x):
        return x.get("source_url") or f"{x['source']}:{x.get('line','?')}"

    sev_color = {"high": C.R, "medium": C.Y, "low": C.GR}
    if secrets:
        print(f"\n{C.BOLD}{C.R}══ SECRETS ({len(secrets)}) ══{C.END}")
        for x in secrets:
            col = sev_color.get(x["severity"], C.W)
            extra = f" entropy={x['entropy']}" if "entropy" in x else ""
            print(f"  {col}[{x['severity'].upper():6}]{C.END} {C.BOLD}{x['rule']}{C.END}{extra}")
            print(f"      {C.CY}{x['match']}{C.END}")
            print(f"      {C.GR}{loc(x)}{C.END}")
    else:
        print(f"\n{C.GR}No secrets matched (min-severity={args.min_severity}).{C.END}")

    if endpoints and not args.quiet:
        print(f"\n{C.BOLD}{C.G}══ ENDPOINTS ({len(endpoints)}) ══{C.END}")
        for e in endpoints[:400]:
            print(f"  {C.G}{e['value']}{C.END}")
        if len(endpoints) > 400:
            print(f"  {C.GR}... +{len(endpoints)-400} more (see output files){C.END}")

    if errors and not args.quiet:
        print(f"\n{C.GR}{len(errors)} source(s) failed{C.END}")

    # ----- files -------------------------------------------------------- #
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"summary": {"sources": len(items), "secrets": len(secrets),
                                   "endpoints": len(endpoints), "chunks": len(chunk_urls),
                                   "errors": len(errors)},
                       "secrets": secrets, "endpoints": endpoints,
                       "chunks": sorted(chunk_urls)}, fh, indent=2)
        print(f"\n{C.B}JSON -> {args.json}{C.END}")

    if args.endpoints_out and endpoints:
        with open(args.endpoints_out, "a") as fh:
            for e in endpoints:
                fh.write(e["value"] + "\n")

    if args.endpoints_detailed and endpoints:
        with open(args.endpoints_detailed, "a") as fh:
            for e in endpoints:
                src = resolve_source(e["source"], url_map) or e["source"]
                fh.write(f"{e['value']}\t{src}\n")

    if args.secrets_out and secrets:
        with open(args.secrets_out, "a") as fh:
            for x in secrets:
                fh.write(f"[{x['severity']}] {x['rule']} | {x['match']} | {loc(x)}\n")

    print(f"\n{C.BOLD}Done.{C.END} {C.R}{len(secrets)} secrets{C.END}, "
          f"{C.G}{len(endpoints)} endpoints{C.END}"
          + (f", {C.M}{len(chunk_urls)} chunks{C.END}" if chunk_urls else "")
          + f" from {len(items)} source(s).")

    if any(x["severity"] == "high" for x in secrets):
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted"); sys.exit(130)
