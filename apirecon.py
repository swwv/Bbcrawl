#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apirecon.py  -  API-surface recon for bug bounty (stdlib only, YAML optional).

Given a list of live hosts / base URLs it will:
  1. SWAGGER/OpenAPI  - probe common spec locations, parse them, and export every
                        path + method + auth requirement (+ params).
  2. GraphQL          - probe common GraphQL endpoints, run an introspection query,
                        save the schema, and list queries / mutations / subscriptions.
  3. WELL-KNOWN       - pull robots.txt, sitemap.xml, security.txt, manifest.json,
                        service-worker.js, assetlinks.json, apple-app-site-association
                        and extract the URLs / paths inside them.
  4. CORS / CSP       - reflectively test Access-Control-Allow-Origin and note
                        whether a Content-Security-Policy header is present.

Honors --proxy / -k / -H / --cookie so it works behind auth or through Burp.

Examples:
  apirecon.py -l live.txt -o out/
  apirecon.py -u https://api.target.com --only swagger,graphql -k
  apirecon.py -l live.txt --graphql-list gql_candidates.txt -o out/
"""

import argparse
import concurrent.futures as cf
import json
import os
import re
import ssl
import sys
import urllib.request
import urllib.parse

try:
    import yaml  # optional; only needed for .yaml/.yml specs
    _HAVE_YAML = True
except Exception:
    _HAVE_YAML = False


class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"; M="\033[95m"
    CY="\033[96m"; GR="\033[90m"; BOLD="\033[1m"; END="\033[0m"
    @staticmethod
    def strip():
        for k in ("R","G","Y","B","M","CY","GR","BOLD","END"): setattr(C,k,"")


SWAGGER_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/api-docs.json",
    "/api/swagger.json", "/api/openapi.json", "/api/api-docs",
    "/v2/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json",
    "/swagger-resources", "/api-docs/swagger.json", "/api/v1/swagger.json",
    "/api/v2/swagger.json", "/docs/swagger.json", "/swagger/docs/v1",
    "/openapi.yaml", "/openapi.yml", "/swagger.yaml", "/swagger.yml",
    "/api/openapi.yaml", "/v3/api-docs.yaml",
]
GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/query",
    "/api/query", "/gql", "/graphql/console", "/graphql-api", "/api/v1/graphql",
]
WELLKNOWN = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/security.txt",
    "/manifest.json", "/manifest.webmanifest",
    "/service-worker.js", "/sw.js", "/serviceworker.js",
    "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
    "/apple-app-site-association",
]
HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options", "trace")

INTROSPECTION = {
    "query": "query IntrospectionQuery { __schema { "
             "queryType { name } mutationType { name } subscriptionType { name } "
             "types { kind name fields { name args { name } } } } }"
}


# --------------------------------------------------------------------------- #
def base_of(u):
    if not re.match(r"^https?://", u):
        u = "https://" + u
    p = urllib.parse.urlparse(u)
    return f"{p.scheme}://{p.netloc}"


def http(url, method="GET", data=None, headers=None, timeout=15, insecure=False, proxy=None):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    h = {"User-Agent": "Mozilla/5.0 (bbcrawl apirecon)"}
    if headers:
        h.update(headers)
    body = data.encode() if isinstance(data, str) else data
    if body is not None and not any(k.lower() == "content-type" for k in h):
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    with opener.open(req, timeout=timeout) as r:
        raw = r.read(4 * 1024 * 1024)
        return r.status, dict(r.headers), raw.decode("utf-8", "replace")


def try_get(url, args, method="GET", data=None):
    try:
        return http(url, method=method, data=data, headers=args._headers,
                    timeout=args.timeout, insecure=args.insecure, proxy=args.proxy)
    except Exception:
        return None, None, None


# --------------------------------------------------------------------------- #
#  Swagger / OpenAPI                                                           #
# --------------------------------------------------------------------------- #
def parse_spec(text, content_type=""):
    data = None
    t = text.lstrip()
    if t.startswith("{") or "application/json" in content_type:
        try:
            data = json.loads(text)
        except Exception:
            data = None
    if data is None and _HAVE_YAML and (t.startswith(("openapi:", "swagger:")) or "yaml" in content_type):
        try:
            data = yaml.safe_load(text)
        except Exception:
            data = None
    if not isinstance(data, dict) or "paths" not in data:
        return None
    return data


def extract_spec_endpoints(spec, spec_url):
    out = []
    base = ""
    if "servers" in spec and isinstance(spec["servers"], list) and spec["servers"]:
        base = str(spec["servers"][0].get("url", "")).rstrip("/")
    elif "basePath" in spec:
        base = str(spec["basePath"]).rstrip("/")
    if base and not re.match(r"^https?://", base):
        base = base_of(spec_url) + base
    if not base:
        base = base_of(spec_url)
    global_sec = bool(spec.get("security"))
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(op, dict):
                op = {}
            if "security" in op:            # op-level overrides global (even empty = public)
                secured = bool(op.get("security"))
            else:
                secured = global_sec
            params = []
            for pr in (op.get("parameters") or []):
                if isinstance(pr, dict) and pr.get("name"):
                    params.append(pr["name"])
            summary = (op.get("summary") or op.get("operationId") or "").strip()
            out.append({
                "method": method.upper(),
                "url": base + path,
                "path": path,
                "auth": "auth" if secured else "public",
                "params": params,
                "summary": summary[:100],
                "spec": spec_url,
            })
    return out


def probe_swagger(baseurl, args):
    found = []
    for p in SWAGGER_PATHS:
        if p.endswith((".yaml", ".yml")) and not _HAVE_YAML:
            continue
        url = baseurl + p
        st, hdr, body = try_get(url, args)
        if not st or st >= 400 or not body:
            continue
        spec = parse_spec(body, (hdr or {}).get("Content-Type", ""))
        if spec:
            eps = extract_spec_endpoints(spec, url)
            if eps:
                found.extend(eps)
    return found


# --------------------------------------------------------------------------- #
#  GraphQL introspection                                                       #
# --------------------------------------------------------------------------- #
def probe_graphql(url, args):
    st, hdr, body = try_get(url, args, method="POST", data=json.dumps(INTROSPECTION))
    if not st or not body:
        return None
    try:
        j = json.loads(body)
    except Exception:
        return None
    schema = (((j or {}).get("data") or {}).get("__schema"))
    if not schema:
        return None
    types = schema.get("types") or []
    qn = (schema.get("queryType") or {}).get("name")
    mn = (schema.get("mutationType") or {}).get("name")
    sn = (schema.get("subscriptionType") or {}).get("name")
    def fields_of(tname):
        for t in types:
            if t.get("name") == tname:
                return [f.get("name") for f in (t.get("fields") or [])]
        return []
    return {
        "endpoint": url,
        "queries": fields_of(qn),
        "mutations": fields_of(mn),
        "subscriptions": fields_of(sn),
        "type_count": len(types),
        "schema": schema,
    }


# --------------------------------------------------------------------------- #
#  Well-known artifacts                                                        #
# --------------------------------------------------------------------------- #
URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>)]+")
PATH_IN_TEXT = re.compile(r"(?m)(?:Allow|Disallow|Sitemap)\s*:\s*(\S+)")


def probe_wellknown(baseurl, args):
    hits, urls = [], set()
    for p in WELLKNOWN:
        url = baseurl + p
        st, hdr, body = try_get(url, args)
        if not st or st >= 400 or not body:
            continue
        ct = (hdr or {}).get("Content-Type", "")
        if "html" in ct and p not in ("/robots.txt",):
            continue  # a catch-all HTML page, not the real artifact
        hits.append(f"{st} {url}")
        for m in URL_IN_TEXT.finditer(body):
            urls.add(m.group(0))
        for m in PATH_IN_TEXT.finditer(body):
            v = m.group(1)
            if v.startswith("http"):
                urls.add(v)
            elif v.startswith("/"):
                urls.add(baseurl + v)
    return hits, urls


# --------------------------------------------------------------------------- #
#  CORS / CSP                                                                  #
# --------------------------------------------------------------------------- #
def probe_cors(baseurl, args):
    evil = "https://evil-bbcrawl.example"
    hdrs = dict(args._headers or {})
    hdrs["Origin"] = evil
    try:
        st, rh, _ = http(baseurl + "/", headers=hdrs, timeout=args.timeout,
                         insecure=args.insecure, proxy=args.proxy)
    except Exception:
        return None
    rh = rh or {}
    acao = rh.get("Access-Control-Allow-Origin", "")
    acac = rh.get("Access-Control-Allow-Credentials", "")
    csp = rh.get("Content-Security-Policy", "")
    notes = []
    if acao == evil:
        notes.append("ACAO reflects arbitrary Origin")
    if acao == "*" and acac.lower() == "true":
        notes.append("wildcard ACAO + credentials")
    if acao == evil and acac.lower() == "true":
        notes.append("origin-reflected + credentials (exploitable CORS)")
    if not csp:
        notes.append("no CSP header")
    if not notes:
        return None
    return {"host": baseurl, "acao": acao, "acac": acac, "csp": bool(csp), "notes": notes}


# --------------------------------------------------------------------------- #
def worker(baseurl, want, args):
    res = {"base": baseurl, "swagger": [], "graphql": [], "wellknown": [],
           "wk_urls": set(), "cors": None}
    if "swagger" in want:
        res["swagger"] = probe_swagger(baseurl, args)
    if "graphql" in want:
        for gp in GRAPHQL_PATHS:
            g = probe_graphql(baseurl + gp, args)
            if g:
                res["graphql"].append(g)
                break  # one working endpoint per host is enough
    if "wellknown" in want:
        res["wellknown"], res["wk_urls"] = probe_wellknown(baseurl, args)
    if "cors" in want:
        res["cors"] = probe_cors(baseurl, args)
    return res


def main():
    ap = argparse.ArgumentParser(description="API-surface recon (swagger/graphql/well-known/cors).",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("-l", "--list", help="file of live hosts / base URLs")
    ap.add_argument("-u", "--url", nargs="+", help="base URL(s)")
    ap.add_argument("--graphql-list", help="explicit GraphQL endpoint candidates (one/line)")
    ap.add_argument("--only", help="comma list: swagger,graphql,wellknown,cors (default all)")
    ap.add_argument("-o", "--outdir", default=".", help="output directory")
    ap.add_argument("-t", "--threads", type=int, default=20)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("-k", "--insecure", action="store_true")
    ap.add_argument("--proxy")
    ap.add_argument("-H", "--header", action="append", default=[], help="extra header 'K: V'")
    ap.add_argument("--cookie")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.strip()

    args._headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            args._headers[k.strip()] = v.strip()
    if args.cookie:
        args._headers["Cookie"] = args.cookie

    bases = []
    if args.list and os.path.isfile(args.list):
        for ln in open(args.list, encoding="utf-8", errors="replace"):
            ln = ln.strip().split()[0] if ln.strip() else ""
            if ln:
                bases.append(base_of(ln))
    if args.url:
        bases += [base_of(u) for u in args.url]
    bases = sorted(set(bases))
    if not bases:
        ap.print_help(); sys.exit(1)

    want = set((args.only.split(",") if args.only else
                ["swagger", "graphql", "wellknown", "cors"]))
    want = {w.strip() for w in want if w.strip()}

    os.makedirs(args.outdir, exist_ok=True)
    if not _HAVE_YAML and "swagger" in want:
        print(f"{C.GR}(note: pyyaml not installed — only JSON specs parsed){C.END}")

    all_api, all_gql, all_wk, all_wk_urls, all_cors = [], [], [], set(), []
    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futs = [ex.submit(worker, b, want, args) for b in bases]
        for fut in cf.as_completed(futs):
            r = fut.result()
            all_api.extend(r["swagger"])
            all_gql.extend(r["graphql"])
            all_wk.extend(r["wellknown"])
            all_wk_urls.update(r["wk_urls"])
            if r["cors"]:
                all_cors.append(r["cors"])

    # extra graphql candidates from a provided list
    if args.graphql_list and os.path.isfile(args.graphql_list) and "graphql" in want:
        seen = {g["endpoint"] for g in all_gql}
        cand = [l.strip() for l in open(args.graphql_list, encoding="utf-8", errors="replace") if l.strip()]
        with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futs = {ex.submit(probe_graphql, u, args): u for u in cand if u not in seen}
            for fut in cf.as_completed(futs):
                g = fut.result()
                if g:
                    all_gql.append(g)

    o = args.outdir
    # ---- swagger/openapi ------------------------------------------------ #
    if all_api:
        uniq = {(e["method"], e["url"]): e for e in all_api}
        api = sorted(uniq.values(), key=lambda e: (e["url"], e["method"]))
        with open(os.path.join(o, "api_endpoints.txt"), "w") as fh:
            for e in api:
                pr = f" params={','.join(e['params'])}" if e["params"] else ""
                sm = f"  # {e['summary']}" if e["summary"] else ""
                fh.write(f"{e['method']:6} [{e['auth']:6}] {e['url']}{pr}{sm}\n")
        json.dump(api, open(os.path.join(o, "api_endpoints.json"), "w"), indent=2)
        pub = sum(1 for e in api if e["auth"] == "public")
        print(f"{C.G}[+]{C.END} swagger/openapi: {C.BOLD}{len(api)}{C.END} ops "
              f"({C.Y}{pub} public{C.END}) -> api_endpoints.txt")
    else:
        print(f"{C.GR}[-] no OpenAPI/Swagger specs found{C.END}")

    # ---- graphql -------------------------------------------------------- #
    if all_gql:
        os.makedirs(os.path.join(o, "graphql"), exist_ok=True)
        with open(os.path.join(o, "graphql_summary.txt"), "w") as fh:
            for g in all_gql:
                host = urllib.parse.urlparse(g["endpoint"]).netloc
                json.dump(g["schema"], open(os.path.join(o, "graphql", host + ".json"), "w"), indent=2)
                fh.write(f"== {g['endpoint']}  (types={g['type_count']})\n")
                fh.write(f"   queries      ({len(g['queries'])}): {', '.join(g['queries'][:60])}\n")
                fh.write(f"   mutations    ({len(g['mutations'])}): {', '.join(g['mutations'][:60])}\n")
                fh.write(f"   subscriptions({len(g['subscriptions'])}): {', '.join(g['subscriptions'][:60])}\n\n")
        print(f"{C.G}[+]{C.END} graphql: introspection succeeded on "
              f"{C.BOLD}{len(all_gql)}{C.END} endpoint(s) -> graphql_summary.txt "
              f"{C.R}(introspection enabled = finding){C.END}")
    else:
        print(f"{C.GR}[-] no GraphQL introspection{C.END}")

    # ---- well-known ----------------------------------------------------- #
    if all_wk:
        with open(os.path.join(o, "wellknown.txt"), "w") as fh:
            fh.write("\n".join(sorted(set(all_wk))) + "\n")
        if all_wk_urls:
            with open(os.path.join(o, "wellknown_urls.txt"), "w") as fh:
                fh.write("\n".join(sorted(all_wk_urls)) + "\n")
        print(f"{C.G}[+]{C.END} well-known artifacts: {C.BOLD}{len(set(all_wk))}{C.END} hit(s), "
              f"{len(all_wk_urls)} urls -> wellknown.txt")
    else:
        print(f"{C.GR}[-] no well-known artifacts{C.END}")

    # ---- cors/csp ------------------------------------------------------- #
    if all_cors:
        with open(os.path.join(o, "cors_csp.txt"), "w") as fh:
            for c in all_cors:
                fh.write(f"{c['host']}  ACAO={c['acao']!r} ACAC={c['acac']!r} CSP={c['csp']}  "
                         f"-> {'; '.join(c['notes'])}\n")
        flagged = [c for c in all_cors if any("credential" in n or "arbitrary" in n for n in c["notes"])]
        print(f"{C.G}[+]{C.END} cors/csp notes: {C.BOLD}{len(all_cors)}{C.END} host(s)"
              + (f" {C.R}({len(flagged)} exploitable-CORS candidates){C.END}" if flagged else "")
              + " -> cors_csp.txt")

    print(f"\n{C.BOLD}apirecon done{C.END} over {len(bases)} host(s).")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted"); sys.exit(130)
