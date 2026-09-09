import urllib.request, urllib.error, rclib
SIGS = {"cloudflare":"Cloudflare","akamai":"Akamai","x-sucuri":"Sucuri","incapsula":"Imperva Incapsula",
        "x-amzn":"AWS WAF/ALB","barracuda":"Barracuda","f5":"F5 BIG-IP","fortiweb":"FortiWeb"}
def run(ctx):
    url = ctx.target if "://" in ctx.target else "https://" + ctx.target
    ctx.info("fingerprinting edge / WAF")
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent":"redcell"}), timeout=15)
        h = {k.lower(): v.lower() for k,v in r.headers.items()}
    except urllib.error.HTTPError as e:
        h = {k.lower(): v.lower() for k,v in e.headers.items()}
    except Exception as e:
        ctx.err(str(e)); return 1
    blob = " ".join(f"{k}:{v}" for k,v in h.items())
    found = [name for sig,name in SIGS.items() if sig in blob]
    if "server" in h: ctx.step("server: " + h["server"])
    if found:
        for f in set(found): ctx.finding(f"WAF/edge detected: {f}", "info")
        ctx.info("bypass hints: try case/encoding mutation, HTTP/2, origin-IP direct, slow-path params")
    else:
        ctx.good("no common WAF signature in headers")
    ctx.data["waf"] = list(set(found))
    return 0
rclib.main("waf-bypass", "WAF/edge fingerprinting + bypass hints", run)
