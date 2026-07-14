#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bbreport.py  -  turn a bbcrawl output dir into prioritised, clickable results.

Reads whatever a bbcrawl run produced (endpoints, JS, params, secrets, api,
graphql, cors, subdomains, screenshots) and generates:

  * prioritized_endpoints.txt  - endpoints classified (Admin/Auth/Payments/...)
                                  and risk-scored 0-100, highest first.
  * endpoints_full.txt         - every known full URL, deduped (feed ffuf/nuclei).
  * wordlist_paths.txt         - target-specific path wordlist for ffuf.
  * wordlist_params.txt        - discovered parameter names for ffuf/arjun.
  * report.html                - one self-contained page: stats, secrets (clickable),
                                 prioritised endpoints (clickable), api, graphql,
                                 cors, subdomains, screenshot gallery.
  * new_*.txt  (incremental)   - endpoints/js/secrets/subdomains new since last run.

Pure standard library. Safe to re-run; missing inputs are skipped.

Usage:  bbreport.py -o recon-target-YYYYMMDD/        # (bbcrawl calls this for you)
"""

import argparse
import html
import json
import os
import re
import sys
import urllib.parse
from collections import defaultdict


def read_lines(path):
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [l.rstrip("\n") for l in fh if l.strip()]
    except Exception:
        return []


# --------------------------------------------------------------------------- #
#  Classification + risk scoring                                              #
# --------------------------------------------------------------------------- #
# (category, base_score, compiled keyword regex)
CATEGORIES = [
    ("Admin",       92, re.compile(r"(?i)(?:^|/)(?:admin|administrator|superuser|manage(?:ment)?|console|backoffice|wp-admin)(?:/|$|\?)")),
    ("Payments",    90, re.compile(r"(?i)(?:^|/)(?:payment|billing|invoice|refund|charge|checkout|wallet|payout|transaction|card|stripe|paypal)(?:/|$|\?|s\b)")),
    ("Uploads",     84, re.compile(r"(?i)(?:^|/)(?:upload|import|attachment|file-?upload|media/upload|blob|document/upload)(?:/|$|\?)")),
    ("Auth",        82, re.compile(r"(?i)(?:^|/)(?:login|logout|signin|signup|register|oauth|token|sso|saml|session|auth|password|reset|forgot|mfa|otp|verify|2fa)(?:/|$|\?)")),
    ("GraphQL",     78, re.compile(r"(?i)(?:^|/)(?:graphql|gql|graphiql)(?:/|$|\?)")),
    ("Debug/Infra", 80, re.compile(r"(?i)(?:^|/)(?:actuator|debug|trace|metrics|heapdump|env|phpinfo|server-status|swagger|api-docs|\.git|\.env|internal)(?:/|$|\?)")),
    ("UserMgmt",    64, re.compile(r"(?i)(?:^|/)(?:users?|account|profile|members?|me|settings|preferences)(?:/|$|\?)")),
    ("API",         56, re.compile(r"(?i)(?:^|/)(?:api|v[0-9]+|rest|service|graph|internalapi)(?:/|$|\?)")),
]
STATIC_RE = re.compile(r"(?i)\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|avif|mp4|webm|mp3|json|xml|txt)(?:$|[?#])")
NEXT_STATIC = re.compile(r"(?i)/_next/static/|/static/chunks/|/assets/")

# risky params -> boost + reason
SSRF_PARAMS = re.compile(r"(?i)(?:^|[?&])(url|uri|redirect|redirect_uri|next|dest|destination|continue|return|returnurl|return_url|callback|cb|goto|link|out|view|file|path|folder|document|load|page|template|include|domain|host|site|feed|data|reference|ref|img|image|src|source|proxy|fetch|remote|target)=")
IDOR_RE = re.compile(r"(?i)(?:/|=)(\d{2,})(?:/|$|&)|/\{?id\}?/|(?:^|[?&])(?:id|uid|user_?id|account_?id|order_?id|doc_?id|file_?id)=")


def classify(u):
    """Return (category, score, reasons[]) for a URL or path."""
    reasons = []
    # static assets: deprioritise hard
    if NEXT_STATIC.search(u) or (STATIC_RE.search(u) and "/api/" not in u.lower()):
        return "Static", 5, ["static asset"]
    cat, score = "Other", 30
    for name, base, rx in CATEGORIES:
        if rx.search(u):
            cat, score = name, base
            reasons.append(f"matched {name}")
            break
    q = u.split("?", 1)[1] if "?" in u else ""
    if q:
        m = SSRF_PARAMS.search("?" + q)
        if m:
            score = min(100, score + 12)
            reasons.append(f"risky param '{m.group(1)}' (SSRF/redirect/LFI)")
    if IDOR_RE.search(u):
        score = min(100, score + 8)
        reasons.append("object id in path/query (IDOR)")
    return cat, score, reasons


# --------------------------------------------------------------------------- #
#  Gather inputs                                                              #
# --------------------------------------------------------------------------- #
def load_all(o):
    d = {}
    d["all_urls"]      = read_lines(os.path.join(o, "all_urls.txt"))
    d["endpoints"]     = read_lines(os.path.join(o, "endpoints.txt"))
    d["js_endpoints"]  = read_lines(os.path.join(o, "endpoints_from_js.txt"))
    d["js"]            = read_lines(os.path.join(o, "js.txt"))
    d["params_urls"]   = read_lines(os.path.join(o, "params_urls.txt"))
    d["param_keys"]    = read_lines(os.path.join(o, "param_keys.txt"))
    d["secrets"]       = read_lines(os.path.join(o, "secrets.txt"))
    d["subdomains"]    = sorted(set(read_lines(os.path.join(o, "subdomains.txt")) +
                                    read_lines(os.path.join(o, "subdomains_from_crawl.txt"))))
    d["live"]          = read_lines(os.path.join(o, "live_detailed.txt"))
    d["sensitive"]     = read_lines(os.path.join(o, "sensitive_files.txt"))
    d["graphql"]       = read_lines(os.path.join(o, "graphql_summary.txt"))
    d["cors"]          = read_lines(os.path.join(o, "cors_csp.txt"))
    d["wellknown"]     = read_lines(os.path.join(o, "wellknown.txt"))
    # endpoint -> source map from jsecret
    d["ep_src"] = {}
    for row in read_lines(os.path.join(o, "endpoints_src.tsv")):
        if "\t" in row:
            ep, src = row.split("\t", 1)
            d["ep_src"].setdefault(ep, src)
    # api endpoints (METHOD [auth] url ...) from apirecon
    d["api"] = []
    for row in read_lines(os.path.join(o, "api_endpoints.txt")):
        m = re.match(r"(\w+)\s+\[(\w+)\s*\]\s+(\S+)", row)
        if m:
            d["api"].append((m.group(1), m.group(2), m.group(3)))
    return d


def full_url_for(ep, all_urls_index):
    """Best-effort clickable URL for an endpoint path."""
    if ep.startswith("http"):
        return ep
    hit = all_urls_index.get(ep)
    if hit:
        return hit
    # match by path suffix
    return None


# --------------------------------------------------------------------------- #
#  Wordlists                                                                  #
# --------------------------------------------------------------------------- #
HASHY = re.compile(r"(?:[0-9a-f]{8,}|[A-Za-z0-9_-]{20,})$")


def path_segments(urls_and_paths):
    segs = set()
    for u in urls_and_paths:
        path = urllib.parse.urlparse(u).path if u.startswith("http") else u.split("?", 1)[0]
        for s in path.split("/"):
            s = s.strip()
            if not s or len(s) > 40:
                continue
            if s.isdigit():
                continue
            if HASHY.match(s) and "." not in s:
                continue
            s = s.split(".")[0] if "." in s else s
            if 1 <= len(s) <= 40 and re.match(r"^[A-Za-z0-9_.\-]+$", s):
                segs.add(s.lower())
    return sorted(segs)


# --------------------------------------------------------------------------- #
#  Incremental diff                                                           #
# --------------------------------------------------------------------------- #
def incremental(o, data):
    state = os.path.join(o, ".bbstate")
    os.makedirs(state, exist_ok=True)
    mapping = {
        "endpoints":  sorted(set(data["endpoints"] + data["js_endpoints"])),
        "js":         sorted(set(data["js"])),
        "secrets":    sorted(set(data["secrets"])),
        "subdomains": sorted(set(data["subdomains"])),
    }
    news = {}
    for key, cur in mapping.items():
        snap = os.path.join(state, key + ".snapshot")
        prev = set(read_lines(snap))
        if prev:
            new = [x for x in cur if x not in prev]
            if new:
                with open(os.path.join(o, f"new_{key}.txt"), "w") as fh:
                    fh.write("\n".join(new) + "\n")
            news[key] = len(new)
        else:
            news[key] = None  # first run
        with open(snap, "w") as fh:
            fh.write("\n".join(cur) + ("\n" if cur else ""))
    return news


# --------------------------------------------------------------------------- #
#  HTML report                                                                #
# --------------------------------------------------------------------------- #
def esc(s):
    return html.escape(str(s), quote=True)


def sev_of_secret(line):
    m = re.match(r"\[(\w+)\]", line)
    return m.group(1).lower() if m else "low"


def build_html(o, data, ranked, news):
    target = os.path.basename(os.path.abspath(o))
    n_ep = len(set(data["endpoints"] + data["js_endpoints"]))
    counts = [
        ("subdomains", len(data["subdomains"])),
        ("live hosts", len(data["live"])),
        ("all urls", len(data["all_urls"])),
        ("endpoints", n_ep),
        ("js files", len(data["js"])),
        ("param names", len(data["param_keys"])),
        ("api ops", len(data["api"])),
        ("secrets", len(data["secrets"])),
    ]
    # screenshots
    shots = []
    sdir = os.path.join(o, "screenshots")
    if os.path.isdir(sdir):
        for fn in sorted(os.listdir(sdir)):
            if fn.lower().endswith((".png", ".jpg", ".jpeg")):
                shots.append("screenshots/" + fn)

    sev_color = {"high": "#ff4d4d", "medium": "#ffb020", "low": "#8a8f98"}
    cat_color = {"Admin": "#ff4d4d", "Payments": "#ff5db1", "Uploads": "#ff8c42",
                 "Auth": "#ffd166", "GraphQL": "#c792ea", "Debug/Infra": "#ff6b6b",
                 "UserMgmt": "#4dd0e1", "API": "#5b9bff", "Other": "#8a8f98",
                 "Static": "#4a4f58"}

    def score_bar(score):
        col = "#ff4d4d" if score >= 80 else "#ffb020" if score >= 55 else "#5b9bff"
        return (f'<div class="bar"><div class="fill" style="width:{score}%;'
                f'background:{col}"></div><span>{score}</span></div>')

    rows_ep = []
    for u, cat, score, reasons in ranked[:600]:
        link = u if u.startswith("http") else esc(u)
        href = f'<a href="{esc(u)}" target="_blank">{esc(u)}</a>' if u.startswith("http") else f'<span class="path">{esc(u)}</span>'
        cc = cat_color.get(cat, "#8a8f98")
        rows_ep.append(
            f'<tr><td>{score_bar(score)}</td>'
            f'<td><span class="chip" style="background:{cc}22;color:{cc};border-color:{cc}55">{esc(cat)}</span></td>'
            f'<td>{href}</td><td class="why">{esc("; ".join(reasons))}</td></tr>')

    rows_sec = []
    for line in sorted(data["secrets"], key=lambda l: {"high":0,"medium":1,"low":2}.get(sev_of_secret(l),3)):
        parts = line.split(" | ")
        sev = sev_of_secret(line)
        rule = esc(parts[0].replace(f"[{sev}]", "").strip()) if parts else ""
        val = esc(parts[1]) if len(parts) > 1 else ""
        src = parts[2] if len(parts) > 2 else ""
        srch = f'<a href="{esc(src.split(" :: ")[0])}" target="_blank">{esc(src)}</a>' if src.startswith("http") else esc(src)
        col = sev_color.get(sev, "#8a8f98")
        rows_sec.append(
            f'<tr><td><span class="chip" style="background:{col}22;color:{col};border-color:{col}55">{esc(sev.upper())}</span></td>'
            f'<td>{rule}</td><td class="mono">{val}</td><td class="src">{srch}</td></tr>')

    rows_api = []
    for meth, auth, url in data["api"][:400]:
        acol = "#ff4d4d" if auth == "public" else "#8a8f98"
        rows_api.append(
            f'<tr><td class="mono">{esc(meth)}</td>'
            f'<td><span class="chip" style="background:{acol}22;color:{acol};border-color:{acol}55">{esc(auth)}</span></td>'
            f'<td><a href="{esc(url)}" target="_blank">{esc(url)}</a></td></tr>')

    def section(title, inner, sub=""):
        if not inner:
            return ""
        subh = f'<span class="sub">{esc(sub)}</span>' if sub else ""
        return f'<section><h2>{esc(title)} {subh}</h2>{inner}</section>'

    stat_html = "".join(f'<div class="stat"><div class="num">{c}</div><div class="lbl">{esc(n)}</div></div>'
                        for n, c in counts)
    new_banner = ""
    if any(v for v in news.values() if v):
        bits = ", ".join(f"{v} new {k}" for k, v in news.items() if v)
        new_banner = f'<div class="newbanner">Δ since last run: {esc(bits)}</div>'

    ep_table = (f'<table><thead><tr><th>risk</th><th>category</th><th>endpoint</th><th>why</th></tr></thead>'
                f'<tbody>{"".join(rows_ep)}</tbody></table>') if rows_ep else ""
    sec_table = (f'<table><thead><tr><th>sev</th><th>rule</th><th>value</th><th>source</th></tr></thead>'
                 f'<tbody>{"".join(rows_sec)}</tbody></table>') if rows_sec else ""
    api_table = (f'<table><thead><tr><th>method</th><th>auth</th><th>url</th></tr></thead>'
                 f'<tbody>{"".join(rows_api)}</tbody></table>') if rows_api else ""
    gql_html = f'<pre>{esc(chr(10).join(data["graphql"]))}</pre>' if data["graphql"] else ""
    cors_html = f'<pre>{esc(chr(10).join(data["cors"]))}</pre>' if data["cors"] else ""
    subs_html = ('<div class="subs">' + "".join(f'<a href="https://{esc(s)}" target="_blank">{esc(s)}</a>'
                 for s in data["subdomains"][:800]) + '</div>') if data["subdomains"] else ""
    shot_html = ('<div class="gallery">' + "".join(
        f'<a href="{esc(s)}" target="_blank"><img loading="lazy" src="{esc(s)}"></a>' for s in shots) + '</div>') if shots else ""

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>bbcrawl report · {esc(target)}</title>
<style>
:root{{--bg:#0d1017;--card:#151a23;--line:#232a36;--fg:#e6e9ef;--mut:#8a8f98;--acc:#5b9bff}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,-apple-system,Segoe UI,Roboto,Helvetica,Arial}}
header{{padding:28px 32px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#121722,#0d1017)}}
header h1{{margin:0;font-size:20px;letter-spacing:.3px}}
header .t{{color:var(--mut);font-size:13px;margin-top:4px}}
.wrap{{max-width:1200px;margin:0 auto;padding:24px 32px 80px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:18px 0}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}}
.stat .num{{font-size:24px;font-weight:600}} .stat .lbl{{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.5px}}
.newbanner{{background:#12331f;border:1px solid #1f5c33;color:#7ee2a8;padding:10px 14px;border-radius:10px;margin:8px 0 20px}}
section{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:18px 0}}
h2{{margin:0 0 14px;font-size:15px;font-weight:600}} h2 .sub{{color:var(--mut);font-weight:400;font-size:12px;margin-left:6px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:var(--card)}}
tr:hover td{{background:#1a2130}}
a{{color:var(--acc);text-decoration:none;word-break:break-all}} a:hover{{text-decoration:underline}}
.chip{{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;border:1px solid}}
.mono,.path,.src{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}}
.why{{color:var(--mut);font-size:12px}} .src{{color:var(--mut)}}
.bar{{position:relative;width:90px;height:16px;background:#0d1017;border:1px solid var(--line);border-radius:6px;overflow:hidden}}
.bar .fill{{position:absolute;left:0;top:0;bottom:0}} .bar span{{position:absolute;right:5px;top:0;font-size:11px;line-height:16px}}
pre{{white-space:pre-wrap;background:#0d1017;border:1px solid var(--line);border-radius:8px;padding:12px;font-size:12px;overflow:auto;max-height:420px}}
.subs{{display:flex;flex-wrap:wrap;gap:6px}} .subs a{{background:#0d1017;border:1px solid var(--line);border-radius:6px;padding:3px 8px;font-size:12px}}
.gallery{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px}}
.gallery img{{width:100%;border:1px solid var(--line);border-radius:8px;display:block}}
.tablewrap{{max-height:640px;overflow:auto;border-radius:8px}}
</style></head><body>
<header><h1>bbcrawl report · {esc(target)}</h1>
<div class="t">Discovery layer — findings are candidates; verify impact by hand. Only act on in-scope assets.</div></header>
<div class="wrap">
{new_banner}
<div class="stats">{stat_html}</div>
{section("Top secrets", ('<div class="tablewrap">'+sec_table+'</div>') if sec_table else "", "verify before reporting — a leaked value is not a finding until you prove access")}
{section("Prioritised endpoints", ('<div class="tablewrap">'+ep_table+'</div>') if ep_table else "", "sorted by risk; click to open")}
{section("API surface (OpenAPI/Swagger)", ('<div class="tablewrap">'+api_table+'</div>') if api_table else "", "public = unauthenticated")}
{section("GraphQL", gql_html)}
{section("CORS / CSP", cors_html)}
{section("Subdomains", subs_html)}
{section("Screenshots", shot_html)}
</div></body></html>"""


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Classify + score + report a bbcrawl output dir.")
    ap.add_argument("-o", "--outdir", required=True, help="the bbcrawl recon output directory")
    ap.add_argument("--no-incremental", action="store_true", help="skip new-since-last-run diff")
    ap.add_argument("--top", type=int, default=40, help="how many prioritised endpoints to print")
    args = ap.parse_args()

    o = args.outdir
    if not os.path.isdir(o):
        print(f"not a directory: {o}", file=sys.stderr); sys.exit(1)

    data = load_all(o)

    # index full URLs by path for clickable resolution
    all_index = {}
    for u in data["all_urls"]:
        p = urllib.parse.urlparse(u).path
        all_index.setdefault(p, u)

    # universe of endpoints to rank: paths + js endpoints + full urls + api urls
    universe = {}
    for ep in set(data["endpoints"] + data["js_endpoints"]):
        full = full_url_for(ep, all_index) or data["ep_src"].get(ep)
        u = full if (full and full.startswith("http")) else ep
        universe[u] = True
    for u in data["all_urls"]:
        universe.setdefault(u, True)
    for _, _, url in data["api"]:
        universe.setdefault(url, True)

    ranked = []
    for u in universe:
        cat, score, reasons = classify(u)
        if cat == "Static":
            continue
        ranked.append((u, cat, score, reasons))
    ranked.sort(key=lambda x: (-x[2], x[1], x[0]))

    # ---- prioritized_endpoints.txt ----
    with open(os.path.join(o, "prioritized_endpoints.txt"), "w") as fh:
        for u, cat, score, reasons in ranked:
            fh.write(f"{score:3d}  {cat:12} {u}"
                     + (f"   ({'; '.join(reasons)})" if reasons else "") + "\n")

    # ---- endpoints_full.txt ----
    full_urls = sorted({u for u in universe if u.startswith("http")})
    with open(os.path.join(o, "endpoints_full.txt"), "w") as fh:
        fh.write("\n".join(full_urls) + ("\n" if full_urls else ""))

    # ---- wordlists ----
    seg_source = [u for u in universe if not NEXT_STATIC.search(u)]
    segs = path_segments(seg_source)
    with open(os.path.join(o, "wordlist_paths.txt"), "w") as fh:
        fh.write("\n".join(segs) + ("\n" if segs else ""))
    params = sorted(set(data["param_keys"]))
    with open(os.path.join(o, "wordlist_params.txt"), "w") as fh:
        fh.write("\n".join(params) + ("\n" if params else ""))

    # ---- incremental ----
    news = {k: None for k in ("endpoints", "js", "secrets", "subdomains")}
    if not args.no_incremental:
        news = incremental(o, data)

    # ---- html ----
    with open(os.path.join(o, "report.html"), "w") as fh:
        fh.write(build_html(o, data, ranked, news))

    # ---- console ----
    hi = [r for r in ranked if r[2] >= 80]
    print(f"prioritised {len(ranked)} endpoints "
          f"({len(hi)} high-risk >=80). top {min(args.top, len(ranked))}:")
    for u, cat, score, reasons in ranked[:args.top]:
        print(f"  {score:3d}  {cat:12} {u}")
    print(f"\nwrote: prioritized_endpoints.txt, endpoints_full.txt, "
          f"wordlist_paths.txt ({len(segs)}), wordlist_params.txt ({len(params)}), report.html")
    newbits = [f"{v} new {k}" for k, v in news.items() if v]
    if newbits:
        print("since last run: " + ", ".join(newbits))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
