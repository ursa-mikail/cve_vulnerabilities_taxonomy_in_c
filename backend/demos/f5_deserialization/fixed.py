import json

attacker_blob = b"cbuiltins\nprint\n(S'  >>> code chosen by the attacker is running inside pickle.loads()'\ntR."
good_blob = b'{"user": "alice", "theme": "dark"}'

def load_session(blob):
    # FIXED: a data-only format (JSON) plus explicit validation of every field. Parsing JSON can
    # only produce strings, numbers, lists and dicts -- never run code or build arbitrary objects.
    data = json.loads(blob.decode("utf-8"))
    if set(data) != {"user", "theme"} or data["theme"] not in {"light", "dark"} or not isinstance(data["user"], str):
        raise ValueError("unexpected session shape")
    return data

print("[demo] a legitimate session:", load_session(good_blob))
print("[demo] the attacker's blob arrives...")
try:
    load_session(attacker_blob)
except Exception as e:
    print(f"       rejected: {type(e).__name__}")
    print("\n[BLOCKED] the bytes were never interpreted as code or objects, only parsed as data and validated.")
