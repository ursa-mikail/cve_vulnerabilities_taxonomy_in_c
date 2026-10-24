import sqlite3

db = sqlite3.connect(":memory:")
db.executescript("""
CREATE TABLE users (name TEXT, is_admin INTEGER);
INSERT INTO users VALUES ('alice', 0), ('bob', 0), ('root', 1);
""")

def find_user(name):
    # VULNERABLE (CWE-89): untrusted text is pasted into the SQL grammar itself.
    query = f"SELECT name, is_admin FROM users WHERE name = '{name}'"
    print(f"[demo] SQL sent to the database: {query}")
    return db.execute(query).fetchall()

print("[demo] a normal lookup, name = alice")
print("       rows:", find_user("alice"))

attacker_input = "x' OR '1'='1"
print(f"\n[demo] attacker supplies name = {attacker_input!r}")
rows = find_user(attacker_input)
print("       rows:", rows)
if len(rows) > 1:
    print(f"\n[ATTACK SUCCEEDED] one lookup for a single user returned all {len(rows)} accounts, admin included.")
