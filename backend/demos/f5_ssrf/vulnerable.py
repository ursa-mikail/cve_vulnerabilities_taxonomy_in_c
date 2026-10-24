from urllib.parse import urlparse

ALLOWED_PREFIX = "https://images.example.com"

def is_allowed(url):
    return url.startswith(ALLOWED_PREFIX)        # VULNERABLE (CWE-918): compares text, not the real host

# This demo only DECIDES whether a fetch would be allowed. It never opens a connection.
tests = [
    "https://images.example.com/cat.png",
    "https://images.example.com.attacker.test/payload",
    "https://images.example.com@169.254.169.254/latest/meta-data/",
]
bypassed = 0
for url in tests:
    real_host = urlparse(url).hostname
    verdict = "ALLOWED" if is_allowed(url) else "refused"
    print(f"[demo] {verdict:8} {url}\n                  the server would really connect to: {real_host}")
    if verdict == "ALLOWED" and real_host != "images.example.com":
        bypassed += 1
if bypassed:
    print(f"\n[ATTACK SUCCEEDED] {bypassed} URLs passed the 'allow-list' yet point at other machines, including the")
    print("                   cloud metadata address 169.254.169.254, which hands out credentials to anyone who can reach it.")
