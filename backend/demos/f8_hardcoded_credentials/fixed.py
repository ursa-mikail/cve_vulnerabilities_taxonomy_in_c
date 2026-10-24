import hashlib, hmac, os, re, secrets

# FIXED: the shipped code contains NO secret. The credential is provisioned per deployment.
def verify(password, salt, expected_hash):
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return hmac.compare_digest(digest, expected_hash)

shipped_source = open(__file__, encoding="utf-8").read()
found = re.findall(r'(?:PASSWORD|SECRET|API_KEY)\w*\s*=\s*"([^"]+)"', shipped_source)
print("[demo] secrets the attacker can extract from the shipped file:", found)

# Simulate the deployment step: a random password and salt are generated for THIS install only.
deployed_password = secrets.token_urlsafe(16)
salt = os.urandom(16)
stored_hash = hashlib.pbkdf2_hmac("sha256", deployed_password.encode(), salt, 200_000)

print("[demo] attacker tries a guess based on the source:", verify("Sup3rS3cret-2019", salt, stored_hash))
if not found:
    print("\n[BLOCKED] nothing useful is in the artifact; each install has its own random secret, stored only as a")
    print("          salted, slow hash, and it can be rotated without shipping new code.")
