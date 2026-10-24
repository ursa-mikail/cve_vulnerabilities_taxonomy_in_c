import hashlib, hmac

legit_update = b"#!/bin/sh\necho 'installing vendor update 2.1'\n"
tampered_by_mirror = b"#!/bin/sh\necho 'attacker code now runs as the updater (often root)'\n"

# FIXED: the expected digest comes from a trusted, separately delivered, signed manifest
# (the vendor's signature on this manifest is what a production updater would verify first).
TRUSTED_MANIFEST = {"update-2.1.sh": hashlib.sha256(legit_update).hexdigest()}

def download(url):
    return tampered_by_mirror

def install(name, blob):
    digest = hashlib.sha256(blob).hexdigest()
    if not hmac.compare_digest(digest, TRUSTED_MANIFEST[name]):
        print(f"[demo] digest mismatch: got {digest[:16]}..., expected {TRUSTED_MANIFEST[name][:16]}...")
        return False
    print("[demo] installing:", blob.decode().splitlines()[1])
    return True

if not install("update-2.1.sh", download("https://updates.example/update-2.1.sh")):
    print("\n[BLOCKED] the tampered file was rejected before it could run. The mirror may be hostile; it cannot forge the")
    print("          vendor's signed manifest.")
