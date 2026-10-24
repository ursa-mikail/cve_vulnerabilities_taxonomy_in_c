import re

ADMIN_PASSWORD = "Sup3rS3cret-2019"      # VULNERABLE (CWE-798): baked into every copy that ships

def login(user, password):
    return user == "admin" and password == ADMIN_PASSWORD

# The attacker has nothing but the shipped artifact: a firmware image, a container layer, a
# public repository, a packaged app. Reading it is enough; no exploit is needed.
shipped_source = open(__file__, encoding="utf-8").read()
found = re.findall(r'(?:PASSWORD|SECRET|API_KEY)\w*\s*=\s*"([^"]+)"', shipped_source)
print("[demo] secrets the attacker pulled out of the shipped file:", found)
if found and login("admin", found[0]):
    print("\n[ATTACK SUCCEEDED] logged in as admin using the extracted password. It is the same password on every")
    print("                   device or install, so one leak compromises all of them and cannot be rotated without a new release.")
