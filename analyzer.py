"""Rule-based QR payload analyzer. Returns a risk score (0-100) with explanations."""
import difflib
import ipaddress
import re
from urllib.parse import urlparse, parse_qs, unquote

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "qrco.de", "l.ead.me"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
              "work", "support", "loan", "icu", "cyou", "rest", "monster", "buzz"}
SECOND_LEVEL = {"co.uk", "co.in", "com.au", "co.jp", "com.br", "co.za", "org.uk", "net.in", "gov.in", "ac.in"}
BRANDS = {  # brand keyword -> official registered domains
    "paypal": {"paypal.com"}, "google": {"google.com"}, "microsoft": {"microsoft.com", "live.com"},
    "apple": {"apple.com", "icloud.com"}, "amazon": {"amazon.com", "amazon.in"},
    "facebook": {"facebook.com"}, "instagram": {"instagram.com"}, "netflix": {"netflix.com"},
    "whatsapp": {"whatsapp.com"}, "paytm": {"paytm.com"}, "phonepe": {"phonepe.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"}, "hdfc": {"hdfcbank.com"}, "icici": {"icicibank.com"},
    "axis": {"axisbank.com"}, "flipkart": {"flipkart.com"}, "dhl": {"dhl.com"},
    "fedex": {"fedex.com"}, "irctc": {"irctc.co.in"}, "binance": {"binance.com"},
}
KEYWORDS = ["login", "signin", "verify", "update", "secure", "account", "password", "bank",
            "wallet", "confirm", "suspend", "unlock", "reward", "prize", "claim", "kyc", "refund"]
BAD_EXT = (".apk", ".exe", ".scr", ".bat", ".msi", ".dmg", ".jar", ".ps1")


def registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_url(raw: str, f: list):
    url = raw if re.match(r"^[a-zA-Z][\w+.-]*://", raw) else "http://" + raw
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if not host:
        f.append(("high", "The link has no valid host name.", 40))
        return

    if p.scheme == "http":
        f.append(("medium", "Uses plain HTTP, so traffic is not encrypted.", 20))
    try:
        ipaddress.ip_address(host)
        f.append(("high", "Points to a raw IP address instead of a domain name.", 30))
    except ValueError:
        pass
    if "@" in p.netloc:
        f.append(("high", "Contains '@' in the address, a trick to hide the real destination.", 25))
    if "xn--" in host or any(ord(c) > 127 for c in host):
        f.append(("high", "Domain uses punycode or look-alike characters (homograph attack).", 30))

    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1]
    if reg in SHORTENERS or host in SHORTENERS:
        f.append(("medium", "URL shortener hides the final destination.", 20))
    if tld in RISKY_TLDS:
        f.append(("medium", f"'.{tld}' is a domain ending frequently abused for scams.", 15))
    if host.count(".") >= 4:
        f.append(("medium", "Unusually many subdomains.", 15))
    if host.count("-") >= 3:
        f.append(("low", "Many hyphens in the domain name.", 10))
    if len(url) > 100:
        f.append(("low", "Very long URL.", 10))
    if p.port and p.port not in (80, 443):
        f.append(("medium", f"Uses a non-standard port ({p.port}).", 10))
    if url.count("%") >= 5:
        f.append(("low", "Heavy percent-encoding may be hiding content.", 10))

    # Brand impersonation: brand name inside the host, but not on the brand's own domain
    label = reg.split(".")[0]
    for brand, official in BRANDS.items():
        if reg in official:
            break
        if brand in host.replace("-", ""):
            f.append(("high", f"Mentions '{brand}' but is not an official {brand} domain ({reg}).", 35))
            break
        if len(label) > 4 and difflib.SequenceMatcher(None, label, brand).ratio() >= 0.82:
            f.append(("high", f"'{label}' looks like a misspelling of '{brand}'.", 35))
            break

    tail = unquote(p.path + "?" + (p.query or "")).lower()
    hits = [k for k in KEYWORDS if k in tail or k in host]
    if hits:
        f.append(("medium", "Pressure or credential words: " + ", ".join(hits[:4]) + ".", min(10 * len(hits), 20)))
    if any(v.lower().startswith("http") for vals in parse_qs(p.query).values() for v in vals):
        f.append(("medium", "Contains a redirect to another site in its parameters.", 15))
    if p.path.lower().endswith(BAD_EXT):
        f.append(("high", "Links directly to an installable or executable file.", 30))


def analyze(content: str) -> dict:
    content = (content or "").strip()
    f: list = []
    low = content.lower()

    if low.startswith("upi://"):
        kind = "UPI payment"
        q = {k: v[0] for k, v in parse_qs(urlparse(content).query).items()}
        f.append(("medium", f"Payment request to {q.get('pn', 'unknown payee')} ({q.get('pa', 'no ID')}). "
                  "Scanning a QR should never be needed to receive money.", 25))
        if "am" in q:
            f.append(("low", f"Pre-filled amount: {q['am']}.", 5))
    elif low.startswith(("bitcoin:", "ethereum:", "litecoin:", "monero:")):
        kind = "Crypto payment"
        f.append(("medium", "Cryptocurrency transfers cannot be reversed.", 30))
    elif low.startswith(("sms:", "smsto:", "tel:")):
        kind = "SMS / phone"
        f.append(("medium", "Can trigger a call or text, possibly to a premium-rate number.", 25))
    elif low.startswith("wifi:"):
        kind = "Wi-Fi login"
        f.append(("medium", "Joins a Wi-Fi network; only continue if you trust the venue.", 20))
        if "t:nopass" in low:
            f.append(("medium", "Open network with no password.", 10))
    elif low.startswith("mailto:"):
        kind = "Email"
        f.append(("low", "Opens an email draft.", 10))
    elif re.match(r"^[a-z][\w+.-]*://", low) or re.match(r"^(www\.)?[\w-]+(\.[\w-]+)+(/\S*)?$", low):
        kind = "Web link"
        analyze_url(content, f)
    else:
        kind = "Plain text"

    if len(content) > 2000:
        f.append(("low", "Unusually large QR payload.", 10))

    score = min(sum(p for _, _, p in f), 100)
    if score >= 55:
        verdict = "dangerous"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return {"content": content, "type": kind, "score": score, "verdict": verdict,
            "findings": [{"level": l, "text": t} for l, t, _ in sorted(f, key=lambda x: -x[2])]}
