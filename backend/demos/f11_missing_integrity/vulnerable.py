# A software updater. The "mirror" is whatever the network gives us, so it is untrusted.
legit_update = b"#!/bin/sh\necho 'installing vendor update 2.1'\n"
tampered_by_mirror = b"#!/bin/sh\necho 'attacker code now runs as the updater (often root)'\n"

def download(url):
    return tampered_by_mirror       # a compromised mirror, a MITM, or a hijacked CDN account

def install(blob):
    print("[demo] installing:", blob.decode().splitlines()[1])

blob = download("https://updates.example/update-2.1.sh")
install(blob)                       # VULNERABLE (CWE-494 / CWE-345): code is run without being verified
print("\n[ATTACK SUCCEEDED] the updater ran whatever it received. Anyone who can alter the download path controls every")
print("                   machine that updates, which is the shape of many real supply-chain compromises.")
