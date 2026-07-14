#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jsecret.py  -  JS/response secret + endpoint extractor for bug bounty recon.

Pure standard library (no pip installs needed). Works on:
  - local .js / .json / .html / .txt files
  - directories (recurses)
  - remote URLs (fetched concurrently)
  - stdin (a list of file paths or URLs, one per line)

It does two jobs:
  1. SECRETS  - ~90 curated provider patterns + generic high-entropy detection
  2. ENDPOINTS- pulls relative/absolute paths, API routes and URLs out of JS

Output: pretty terminal report and/or machine-readable JSON (--json out.json).

Examples:
  python3 jsecret.py -f app.js
  python3 jsecret.py -d ./js_downloaded --json findings.json
  cat js_urls.txt | python3 jsecret.py --stdin --fetch --threads 30
  python3 jsecret.py -u https://target.com/main.js --only-secrets
"""

import argparse
import concurrent.futures as cf
import hashlib
import json
import math
import os
import re
import sys
import urllib.request
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
#  Secret patterns   (name, compiled regex, severity)                         #
#  Severity: high = live credential likely, medium = sensitive, low = info    #
# --------------------------------------------------------------------------- #
_RAW_PATTERNS = [
    # ---- Cloud providers ------------------------------------------------- #
    ("AWS Access Key ID",        r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b", "high"),
    ("AWS Secret Access Key",    r"(?i)aws(.{0,20})?(?:secret|sk)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]", "high"),
    ("AWS MWS Auth Token",       r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "high"),
    ("AWS Session Token",        r"(?i)aws_session_token['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{100,}['\"]", "high"),
    ("Google API Key",           r"\bAIza[0-9A-Za-z\-_]{35}\b", "high"),
    ("Google OAuth Client ID",   r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", "medium"),
    ("Google OAuth Secret",      r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b", "high"),
    ("GCP Service Account",      r"\"type\":\s*\"service_account\"", "high"),
    ("Firebase URL",             r"https://[a-z0-9.-]+\.firebaseio\.com", "medium"),
    ("Firebase Cloud Msg Key",   r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b", "high"),
    ("Azure Storage Key",        r"(?i)AccountKey=[A-Za-z0-9+/=]{88}", "high"),
    ("Azure Connection String",  r"(?i)DefaultEndpointsProtocol=https?;AccountName=", "high"),
    ("Azure AD Client Secret",   r"(?i)client_secret['\"]?\s*[:=]\s*['\"][0-9A-Za-z\-_.~]{34,40}['\"]", "high"),
    ("DigitalOcean Token",       r"\bdop_v1_[a-f0-9]{64}\b", "high"),
    ("DigitalOcean OAuth",       r"\bdoo_v1_[a-f0-9]{64}\b", "high"),
    ("Heroku API Key",           r"(?i)heroku(.{0,20})?['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]", "high"),

    # ---- Version control / CI -------------------------------------------- #
    ("GitHub PAT (classic)",     r"\bghp_[0-9A-Za-z]{36}\b", "high"),
    ("GitHub Fine-grained PAT",  r"\bgithub_pat_[0-9A-Za-z_]{82}\b", "high"),
    ("GitHub OAuth Token",       r"\bgho_[0-9A-Za-z]{36}\b", "high"),
    ("GitHub App Token",         r"\b(?:ghu|ghs)_[0-9A-Za-z]{36}\b", "high"),
    ("GitHub Refresh Token",     r"\bghr_[0-9A-Za-z]{36}\b", "high"),
    ("GitLab PAT",               r"\bglpat-[0-9A-Za-z\-_]{20}\b", "high"),
    ("GitLab Pipeline Token",    r"\bglptt-[0-9a-f]{40}\b", "high"),
    ("NPM Access Token",         r"\bnpm_[0-9A-Za-z]{36}\b", "high"),
    ("PyPI Upload Token",        r"\bpypi-AgEIcHlwaS[0-9A-Za-z\-_]{50,}\b", "high"),
    ("Docker Hub PAT",           r"\bdckr_pat_[0-9A-Za-z\-_]{27,}\b", "high"),

    # ---- Payments -------------------------------------------------------- #
    ("Stripe Live Secret Key",   r"\bsk_live_[0-9a-zA-Z]{24,}\b", "high"),
    ("Stripe Live Restricted",   r"\brk_live_[0-9a-zA-Z]{24,}\b", "high"),
    ("Stripe Test Secret Key",   r"\bsk_test_[0-9a-zA-Z]{24,}\b", "medium"),
    ("Stripe Publishable Key",   r"\bpk_live_[0-9a-zA-Z]{24,}\b", "low"),
    ("Square Access Token",      r"\bsq0atp-[0-9A-Za-z\-_]{22}\b", "high"),
    ("Square OAuth Secret",      r"\bsq0csp-[0-9A-Za-z\-_]{43}\b", "high"),
    ("PayPal Braintree Token",   r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b", "high"),
    ("Razorpay Key",             r"\brzp_(?:live|test)_[0-9A-Za-z]{14}\b", "medium"),

    # ---- Comms / email / SMS --------------------------------------------- #
    ("Slack Token",              r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b", "high"),
    ("Slack Webhook",            r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,}/B[0-9A-Za-z_]{8,}/[0-9A-Za-z_]{24}", "high"),
    ("Discord Bot Token",        r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b", "high"),
    ("Discord Webhook",          r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z_-]{60,68}", "medium"),
    ("Telegram Bot Token",       r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b", "high"),
    ("Twilio API Key",           r"\bSK[0-9a-fA-F]{32}\b", "high"),
    ("Twilio Account SID",       r"\bAC[0-9a-fA-F]{32}\b", "medium"),
    ("SendGrid API Key",         r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b", "high"),
    ("Mailgun API Key",          r"\bkey-[0-9a-zA-Z]{32}\b", "high"),
    ("Mailchimp API Key",        r"\b[0-9a-f]{32}-us[0-9]{1,2}\b", "high"),
    ("Postmark Server Token",    r"(?i)postmark(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "high"),
    ("Nexmo/Vonage API Secret",  r"(?i)nexmo(.{0,20})?['\"][0-9a-zA-Z]{16}['\"]", "high"),

    # ---- SaaS / infra ---------------------------------------------------- #
    ("Datadog API Key",          r"(?i)datadog(.{0,20})?['\"][0-9a-f]{32}['\"]", "high"),
    ("New Relic License",        r"\bNRAK-[0-9A-Z]{27}\b", "high"),
    ("New Relic Insights Key",   r"\bNRJS-[0-9a-f]{19}\b", "medium"),
    ("PagerDuty Token",          r"\b[0-9a-z]{20}@pdt\b", "high"),
    ("Cloudflare API Token",     r"(?i)cloudflare(.{0,20})?['\"][A-Za-z0-9_-]{40}['\"]", "high"),
    ("Cloudflare Global Key",    r"(?i)x-auth-key['\"]?\s*[:=]\s*['\"][0-9a-f]{37}['\"]", "high"),
    ("Algolia Admin Key",        r"(?i)algolia(.{0,20})?(?:admin|api)(.{0,20})?['\"][0-9a-f]{32}['\"]", "high"),
    ("Contentful Token",         r"(?i)contentful(.{0,20})?['\"][0-9A-Za-z\-_]{43}['\"]", "medium"),
    ("Sentry DSN",               r"https://[0-9a-f]{32}@[0-9a-z.-]+/[0-9]+", "medium"),
    ("Segment Write Key",        r"(?i)segment(.{0,20})?(?:write_key|writeKey)(.{0,20})?['\"][0-9A-Za-z]{32}['\"]", "medium"),
    ("Airtable API Key",         r"\bkey[0-9A-Za-z]{14}\b", "medium"),
    ("Airtable PAT",             r"\bpat[0-9A-Za-z]{14}\.[0-9a-f]{64}\b", "high"),
    ("Shopify Access Token",     r"\bshpat_[0-9a-fA-F]{32}\b", "high"),
    ("Shopify Custom App Token", r"\bshpca_[0-9a-fA-F]{32}\b", "high"),
    ("Shopify Shared Secret",    r"\bshpss_[0-9a-fA-F]{32}\b", "high"),
    ("Shopify Private App",      r"\bshppa_[0-9a-fA-F]{32}\b", "high"),
    ("Linear API Key",           r"\blin_api_[0-9A-Za-z]{40}\b", "high"),
    ("Notion Integration Token", r"\bsecret_[0-9A-Za-z]{43}\b", "high"),
    ("Asana PAT",                r"\b[0-9]/[0-9]{16}:[0-9a-f]{32}\b", "high"),
    ("Atlassian API Token",      r"\bATATT3[0-9A-Za-z_\-]{180,}\b", "high"),
    ("Dropbox Token",            r"\bsl\.[0-9A-Za-z_-]{130,152}\b", "high"),
    ("Okta API Token",           r"(?i)okta(.{0,20})?['\"]00[0-9A-Za-z_-]{40}['\"]", "high"),
    ("Hubspot API Key",          r"(?i)hubspot(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "high"),
    ("Intercom Access Token",    r"(?i)intercom(.{0,20})?['\"]dG9r[0-9A-Za-z=_-]{20,}['\"]", "high"),

    # ---- Databases ------------------------------------------------------- #
    ("Postgres URI",             r"postgres(?:ql)?://[^\s:@/]+:[^\s:@/]+@[^\s/]+", "high"),
    ("MySQL URI",                r"mysql://[^\s:@/]+:[^\s:@/]+@[^\s/]+", "high"),
    ("MongoDB URI",              r"mongodb(?:\+srv)?://[^\s:@/]+:[^\s:@/]+@[^\s/]+", "high"),
    ("Redis URI",                r"redis://[^\s:@/]*:[^\s:@/]+@[^\s/]+", "high"),
    ("JDBC Connection",          r"jdbc:[a-z]+://[^\s;]+;?(?:user|password)=", "high"),

    # ---- Generic keys / auth --------------------------------------------- #
    ("JWT",                      r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "medium"),
    ("Basic Auth in URL",        r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@[a-z0-9.-]+", "high"),
    ("Bearer Token",             r"(?i)bearer\s+[a-z0-9\-_.=]{20,}", "medium"),
    ("Authorization Header",     r"(?i)authorization['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-._~+/]{20,}['\"]", "medium"),
    ("Private Key Block",        r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)? ?PRIVATE KEY(?: BLOCK)?-----", "high"),
    ("SSH Private Key",          r"-----BEGIN OPENSSH PRIVATE KEY-----", "high"),
    ("PuTTY Private Key",        r"PuTTY-User-Key-File-[23]:", "high"),
    ("Generic API Key assign",   r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_.=]{16,}['\"]", "medium"),
    ("Generic Password assign",  r"(?i)(?:password|passwd|pwd|db[_-]?pass)['\"]?\s*[:=]\s*['\"][^'\"\s]{6,}['\"]", "medium"),
]

PATTERNS = [(name, re.compile(rx), sev) for name, rx, sev in _RAW_PATTERNS]

# Values that look like secrets but almost never are -> suppress noise.
FALSE_POSITIVE = re.compile(
    r"(?i)^(?:"
    r"(?:x{4,}|0{6,}|1234567890|abcdef0123|deadbeef|null|undefined|example|"
    r"your[_-]?(?:api|key|token|secret)|placeholder|changeme|test[_-]?key|"
    r"[a-f0-9]{0,4})$"
    r")"
)

# --------------------------------------------------------------------------- #
#  Endpoint extraction (LinkFinder-derived regex, MIT)                        #
# --------------------------------------------------------------------------- #
ENDPOINT_RE = re.compile(r"""
  (?:"|'|`)                                # opening quote
  (
    ((?:[a-zA-Z]{1,10}://|//)              # scheme  //  or  https://
      [^"'`/]{1,}\.[a-zA-Z]{2,}[^"'`]{0,}) # host + path
    |
    ((?:/|\.\./|\./)                       # relative path start
      [^"'`><,;| *()(%$^/\\\[\]][^"'`><,;|()]{1,})
    |
    ([a-zA-Z0-9_\-/]{1,}/                  # dir/file.ext
      [a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)
      (?:[\?|#][^"|'`]{0,}|))
    |
    ([a-zA-Z0-9_\-/]{1,}/                  # dir/route
      [a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|'`]{0,}|))
    |
    ([a-zA-Z0-9_\-]{1,}                    # file.ext (api-ish)
      \.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)
      (?:[\?|#][^"|'`]{0,}|))
  )
  (?:"|'|`)                                # closing quote
""", re.VERBOSE)

# Reject obvious non-endpoints from the endpoint regex.
ENDPOINT_REJECT = re.compile(
    r"(?i)\.(?:png|jpe?g|gif|svg|ico|woff2?|ttf|eot|css|map|mp4|webp|webm|"
    r"avif|bmp)(?:$|[?#])|^(?:text/|image/|application/|application$|"
    r"[0-9.]+$|https?://(?:www\.)?w3\.org|use strict)"
)

SECRETY_KEYWORDS = re.compile(r"(?i)(secret|token|apikey|api_key|passwd|password|auth|credential|private)")


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for ch in data:
        freq[ch] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def redact(value: str) -> str:
    v = value.strip().strip("'\"`")
    if len(v) <= 12:
        return v[:3] + "…"
    return f"{v[:6]}…{v[-4:]} (len {len(v)})"


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


# --------------------------------------------------------------------------- #
#  Core extraction                                                            #
# --------------------------------------------------------------------------- #
def scan_secrets(source: str, text: str, entropy_min: float, high_only: bool):
    out = []
    seen = set()
    for name, rx, sev in PATTERNS:
        if high_only and sev != "high":
            continue
        for m in rx.finditer(text):
            raw = m.group(0)
            # extract the quoted value if the pattern captured a wider context
            val_match = re.search(r"['\"`]([^'\"`]{6,})['\"`]\s*$", raw)
            val = val_match.group(1) if val_match else raw
            key = (name, val)
            if key in seen:
                continue
            if FALSE_POSITIVE.match(val.strip("'\"` ")):
                continue
            seen.add(key)
            out.append({
                "type": "secret",
                "rule": name,
                "severity": sev,
                "match": redact(raw),
                "source": source,
                "line": line_of(text, m.start()),
            })

    # Generic high-entropy hunt: long tokens that sit next to a secret-y word.
    for m in re.finditer(r"['\"`]([A-Za-z0-9\-_+/=]{24,80})['\"`]", text):
        token = m.group(1)
        if token in {t for (_, t) in seen}:
            continue
        window = text[max(0, m.start() - 40): m.start()]
        if not SECRETY_KEYWORDS.search(window):
            continue
        ent = shannon_entropy(token)
        if ent < entropy_min or FALSE_POSITIVE.match(token):
            continue
        key = ("High-Entropy String", token)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "type": "secret",
            "rule": "High-Entropy String",
            "severity": "low",
            "entropy": round(ent, 2),
            "match": redact(token),
            "source": source,
            "line": line_of(text, m.start()),
        })
    return out


_KEYLIKE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def _looks_like_leaked_key(ep: str) -> bool:
    # A bare token with no dot, not rooted at '/', pure base64-ish charset and
    # high entropy is almost always a leaked secret, not a route.
    if ep.startswith(("/", "./", "../")) or "://" in ep or "." in ep:
        return False
    if not _KEYLIKE.match(ep):
        return False
    if len(ep) >= 20 and shannon_entropy(ep) > 4.0:
        return True
    return False


def scan_endpoints(source: str, text: str):
    endpoints = set()
    for m in ENDPOINT_RE.finditer(text):
        ep = m.group(1)
        if not ep:
            continue
        ep = ep.strip()
        if len(ep) < 3 or len(ep) > 400:
            continue
        if ENDPOINT_REJECT.search(ep):
            continue
        if _looks_like_leaked_key(ep):
            continue
        endpoints.add(ep)
    return [{"type": "endpoint", "value": e, "source": source} for e in sorted(endpoints)]


# --------------------------------------------------------------------------- #
#  Input handling                                                             #
# --------------------------------------------------------------------------- #
def fetch(url: str, timeout: int, insecure: bool):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (bbcrawl jsecret)"
    })
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        raw = r.read(8 * 1024 * 1024)  # cap 8MB
    return raw.decode("utf-8", "replace")


def read_file(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(16 * 1024 * 1024)
    except Exception:
        return None


def gather_inputs(args):
    items = []  # list of (label, kind) kind in {"file","url"}
    if args.file:
        for f in args.file:
            items.append((f, "file"))
    if args.dir:
        exts = (".js", ".json", ".html", ".htm", ".txt", ".xml", ".map")
        for root, _, files in os.walk(args.dir):
            for fn in files:
                if fn.lower().endswith(exts):
                    items.append((os.path.join(root, fn), "file"))
    if args.url:
        for u in args.url:
            items.append((u, "url"))
    if args.stdin:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            if line.startswith("http://") or line.startswith("https://"):
                items.append((line, "url" if args.fetch else "url"))
            else:
                items.append((line, "file"))
    return items


# --------------------------------------------------------------------------- #
#  Driver                                                                      #
# --------------------------------------------------------------------------- #
def process(label, kind, args):
    if kind == "url":
        try:
            text = fetch(label, args.timeout, args.insecure)
        except Exception as e:
            return label, None, f"fetch error: {e}"
    else:
        text = read_file(label)
        if text is None:
            return label, None, "read error"
    findings = []
    if not args.only_endpoints:
        findings += scan_secrets(label, text, args.entropy, args.high_only)
    if not args.only_secrets:
        findings += scan_endpoints(label, text)
    return label, findings, None


def main():
    ap = argparse.ArgumentParser(
        description="Extract secrets + endpoints from JS / responses (stdlib only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = ap.add_argument_group("inputs")
    src.add_argument("-f", "--file", nargs="+", help="one or more local files")
    src.add_argument("-d", "--dir", help="directory to recurse for js/json/html")
    src.add_argument("-u", "--url", nargs="+", help="remote URL(s) to fetch")
    src.add_argument("--stdin", action="store_true", help="read paths/URLs from stdin")
    src.add_argument("--fetch", action="store_true", help="treat stdin http(s) lines as fetchable URLs")

    filt = ap.add_argument_group("filters")
    filt.add_argument("--only-secrets", action="store_true")
    filt.add_argument("--only-endpoints", action="store_true")
    filt.add_argument("--high-only", action="store_true", help="only high-severity secret rules")
    filt.add_argument("--entropy", type=float, default=3.5, help="min entropy for generic tokens (default 3.5)")

    net = ap.add_argument_group("network")
    net.add_argument("-t", "--threads", type=int, default=20)
    net.add_argument("--timeout", type=int, default=15)
    net.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")

    outg = ap.add_argument_group("output")
    outg.add_argument("--json", help="write JSON results to this path")
    outg.add_argument("--endpoints-out", help="append discovered endpoints (one per line)")
    outg.add_argument("--secrets-out", help="append secret findings (one per line)")
    outg.add_argument("--no-color", action="store_true")
    outg.add_argument("-q", "--quiet", action="store_true", help="only print secrets to terminal")

    args = ap.parse_args()
    if args.no_color or not sys.stdout.isatty():
        C.strip()

    items = gather_inputs(args)
    if not items:
        ap.print_help()
        sys.exit(1)

    all_findings = []
    errors = []
    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futs = [ex.submit(process, lbl, kind, args) for lbl, kind in items]
        for fut in cf.as_completed(futs):
            label, findings, err = fut.result()
            if err:
                errors.append((label, err))
                continue
            all_findings.extend(findings)

    secrets = [f for f in all_findings if f["type"] == "secret"]
    endpoints = [f for f in all_findings if f["type"] == "endpoint"]

    # de-dupe endpoints globally
    uniq_ep, seen_ep = [], set()
    for e in endpoints:
        if e["value"] not in seen_ep:
            seen_ep.add(e["value"])
            uniq_ep.append(e)
    endpoints = uniq_ep

    sev_rank = {"high": 0, "medium": 1, "low": 2}
    secrets.sort(key=lambda x: (sev_rank.get(x["severity"], 3), x["rule"]))

    # ---- terminal report ------------------------------------------------- #
    sev_color = {"high": C.R, "medium": C.Y, "low": C.GR}
    if secrets:
        print(f"\n{C.BOLD}{C.R}══ SECRETS ({len(secrets)}) ══{C.END}")
        for s in secrets:
            col = sev_color.get(s["severity"], C.W)
            extra = f" entropy={s['entropy']}" if "entropy" in s else ""
            print(f"  {col}[{s['severity'].upper():6}]{C.END} "
                  f"{C.BOLD}{s['rule']}{C.END}{extra}")
            print(f"      {C.CY}{s['match']}{C.END}")
            print(f"      {C.GR}{s['source']}:{s['line']}{C.END}")
    else:
        print(f"\n{C.GR}No secrets matched.{C.END}")

    if endpoints and not args.quiet:
        print(f"\n{C.BOLD}{C.G}══ ENDPOINTS ({len(endpoints)}) ══{C.END}")
        for e in endpoints:
            print(f"  {C.G}{e['value']}{C.END}")

    if errors and not args.quiet:
        print(f"\n{C.GR}{len(errors)} source(s) failed:{C.END}")
        for lbl, err in errors[:15]:
            print(f"  {C.GR}- {lbl}: {err}{C.END}")

    # ---- files ----------------------------------------------------------- #
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({
                "summary": {
                    "sources": len(items),
                    "secrets": len(secrets),
                    "endpoints": len(endpoints),
                    "errors": len(errors),
                },
                "secrets": secrets,
                "endpoints": endpoints,
            }, fh, indent=2)
        print(f"\n{C.B}JSON written -> {args.json}{C.END}")

    if args.endpoints_out and endpoints:
        with open(args.endpoints_out, "a") as fh:
            for e in endpoints:
                fh.write(e["value"] + "\n")

    if args.secrets_out and secrets:
        with open(args.secrets_out, "a") as fh:
            for s in secrets:
                fh.write(f"[{s['severity']}] {s['rule']} | {s['match']} | {s['source']}:{s['line']}\n")

    print(f"\n{C.BOLD}Done.{C.END} "
          f"{C.R}{len(secrets)} secrets{C.END}, "
          f"{C.G}{len(endpoints)} endpoints{C.END} "
          f"from {len(items)} source(s).")

    # exit non-zero if high-severity secrets found (useful in CI)
    if any(s["severity"] == "high" for s in secrets):
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)
