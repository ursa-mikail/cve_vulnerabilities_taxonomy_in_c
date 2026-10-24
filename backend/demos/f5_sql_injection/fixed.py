import sqlite3

db = sqlite3.connect(":memory:")
db.executescript("""
CREATE TABLE users (name TEXT, is_admin INTEGER);
INSERT INTO users VALUES ('alice', 0), ('bob', 0), ('root', 1);
""")

def find_user(name):
    # FIXED: the query text is constant; the value travels separately as DATA and can
    # never change the structure of the statement.
    query = "SELECT name, is_admin FROM users WHERE name = ?"
    print(f"[demo] SQL sent to the database: {query}   parameters: {(name,)!r}")
    return db.execute(query, (name,)).fetchall()

print("[demo] a normal lookup, name = alice")
print("       rows:", find_user("alice"))

attacker_input = "x' OR '1'='1"
print(f"\n[demo] attacker supplies name = {attacker_input!r}")
rows = find_user(attacker_input)
print("       rows:", rows)
if not rows:
    print("\n[BLOCKED] the whole string was treated as one (non-existent) user name; nothing leaked.")
