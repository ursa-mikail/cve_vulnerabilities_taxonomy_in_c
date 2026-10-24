import ipaddress
from urllib.parse import urlparse

ALLOWED_HOSTS = {"images.example.com"}

def is_allowed(url):
    p = urlparse(url)
    if p.scheme != "https" or p.username or p.password or p.port not in (None, 443):
        return False
    host = p.hostname or ""
    try:                                          # literal IPs are never acceptable here
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return host in ALLOWED_HOSTS                  # FIXED: exact match on the PARSED host

tests = [
    "https://images.example.com/cat.png",
    "https://images.example.com.attacker.test/payload",
    "https://images.example.com@169.254.169.254/latest/meta-data/",
]
bypassed = 0
for url in tests:
    real_host = urlparse(url).hostname
    verdict = "ALLOWED" if is_allowed(url) else "refused"
    print(f"[demo] {verdict:8} {url}\n                  parsed host: {real_host}")
    if verdict == "ALLOWED" and real_host != "images.example.com":
        bypassed += 1
if not bypassed:
    print("\n[BLOCKED] only the real images host is accepted; look-alike and userinfo tricks are refused.")
    print("          (A production fix also resolves DNS once, checks the IP is public, and connects to that IP.)")
