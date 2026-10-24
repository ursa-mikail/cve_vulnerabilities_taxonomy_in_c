"""Rules used by repair_mapping.py. Kept separate so they can be read, tested and argued with.

Principle: IMPACT words ("execute arbitrary code", "denial of service", "privilege escalation")
say what an attacker gets, not what went wrong. A family claim made by a keyword refinement is only
kept when the description contains an explicit WEAKNESS term for that family.
"""
import re

I = re.I
EVIDENCE = {
    "F1": re.compile(r"buffer|overflow|out[- ]of[- ]bounds|\boob\b|heap|stack[- ]based|bounds|over-?read|overrun|memory corruption|memory[- ]safety|off-by-one|underflow", I),
    "F2": re.compile(r"use[- ]after[- ]free|double[- ]free|dangling|null pointer|null[- ]dereference|uninitiali[sz]ed|use after|invalid pointer|invalid free", I),
    "F3": re.compile(r"integer|wrap-?around|divide[- ]by[- ]zero|truncat|signedness|sign extension", I),
    "F4": re.compile(r"type confusion|type juggling|incorrect cast|wrong type", I),
    "F5": re.compile(r"inject|ognl|shell metachar|command|\beval\b|template|expression language|deserializ|traversal|cross-?(site|zone) scripting|\bxss\b|\bsql\b|xml external|\bxxe\b|ssrf|server-side request|file inclusion|\binclude\b|upload|open redirect|format string|crlf|response splitting|prototype pollution|symlink|symbolic link|\.\./", I),
    "F6": re.compile(r"race|toctou|time-of-check|deadlock|concurren|synchroniz|thread", I),
    "F7": re.compile(r"exhaust|consum|infinite loop|leak|unbounded|excessive|redos|regular expression|complexity|recursion|amplification|decompression|bomb|flood|allocation", I),
    "F8": re.compile(r"crypto|certificate|\btls\b|\bssl\b|encrypt|random|hard-?coded|cleartext|clear text|plaintext|plain text|password|credential|\bhash|\bkey\b|\bsecret", I),
    # strict: "privilege" alone is usually an impact ("escalation of privilege"), so it is not evidence
    "F9": re.compile(r"authenticat|authoriz|access control|permission|\bacl\b|session|csrf|cross-site request|unauthorized access", I),
    "F10": re.compile(r"information (disclosure|exposure|leak)|expos(e|es|ure|ing) (of )?(sensitive|private|confidential)|side[- ]channel|timing|leak|discloses|obtain sensitive", I),
    "F11": re.compile(r"integrity|signature|supply chain|dependenc|insecure default|default (config|setting|password)|misconfigur|debug|search path|\bdll\b|update|backdoor|malicious code|unsigned", I),
    "F12": re.compile(r"logic|error handling|exception|unchecked return|return value|incorrect (check|comparison|calculation)|workflow|fail(s|ure)? (open|to handle)", I),
    "F13": re.compile(r"firmware|bios|\bsmm\b|\bsmi\b|microcode|secure boot|uefi|hardware|debug (port|interface)|jtag|bootloader", I),
    "F14": re.compile(r"clickjack|spoof|user interface|\bui\b|homograph|x-frame|address bar|overlay|dialog|phishing|redress", I),
}

# Where an umbrella CWE belongs when the description names no specific weakness.
GENERIC_HOME = {
    "CWE-119": ("F1", "Buffer bounds (generic)"),
    "CWE-20":  ("F5", "Generic improper input validation"),
    "CWE-74":  ("F5", "Injection (generic)"),
    "CWE-77":  ("F5", "OS command / argument injection"),
    "CWE-255": ("F8", "Cryptographic issues (generic)"),
    "CWE-264": ("F9", "Access control (generic)"),
    "CWE-284": ("F9", "Access control (generic)"),
    "CWE-399": ("F7", "Uncontrolled resource consumption / DoS"),
    "CWE-16":  ("F11", "Insecure default / configuration / debug"),
    "CWE-668": ("F9", "Access control (generic)"),
    "CWE-693": ("F11", "Missing integrity or authenticity verification"),
    "CWE-754": ("F12", "Unchecked or mishandled error / exception"),
}
# Umbrella CWEs whose own definition fixes the family: a refinement away needs explicit evidence.
# (CWE-20, CWE-189, CWE-310 are deliberately NOT here: they have no single right home, and the
#  v3 refinements I sampled for CWE-310 -- hash-collision CPU exhaustion -- were correct.)
GATED = {"CWE-119", "CWE-74", "CWE-77", "CWE-255", "CWE-264", "CWE-284", "CWE-399", "CWE-16",
         "CWE-668", "CWE-693", "CWE-754"}
MEMORY_FAMILIES = {"F1", "F2", "F3", "F4"}

# Wrong family inherited from an over-general ancestor CWE in v3 ("CWE hierarchy (ancestor ...)").
CWE_OVERRIDES = {
    "CWE-134": ("F5", "Format string injection", "externally-controlled format string is input interpreted as a directive; v3 inherited F9 from ancestor CWE-668"),
    "CWE-591": ("F10", "Sensitive information exposure", "sensitive data left in swappable memory is an exposure, not a locking bug; v3 inherited F6 from CWE-413"),
    "CWE-226": ("F10", "Sensitive information exposure", "information residue is an exposure; v3 inherited F7 from CWE-459"),
    "CWE-244": ("F10", "Sensitive information exposure", "un-cleared heap memory is an exposure; v3 inherited F7 from CWE-459"),
    "CWE-402": ("F10", "Sensitive information exposure", "private resource sent to a new sphere is an exposure; v3 inherited F9 from CWE-668"),
    "CWE-837": ("F12", "Incorrect control flow or logic", "a once-only action enforced twice is a logic flaw, not exhaustion; v3 inherited F7 from CWE-799"),
}

MEMORY_KEEP = re.compile(
    EVIDENCE["F1"].pattern + "|" + EVIDENCE["F2"].pattern + "|" + EVIDENCE["F3"].pattern + "|" + EVIDENCE["F4"].pattern +
    r"|memory|crash|segfault|segmentation|pointer|malformed|corrupt|dereference|\bnull\b", I)

# First match wins. Used when a "Memory corruption (unspecified)" label has no memory evidence.
LADDER = [
    (re.compile(r"format string", I), "F5", "Format string injection"),
    (re.compile(r"cross-?(site|zone) scripting|\bxss\b", I), "F5", "Cross-site scripting (XSS)"),
    (re.compile(r"\bsql\b", I), "F5", "SQL injection"),
    (re.compile(r"traversal|\.\./", I), "F5", "Path traversal / link following"),
    (re.compile(r"deserializ|unserializ", I), "F5", "Unsafe deserialization"),
    (re.compile(r"ognl|expression language|template|\beval\b|code injection|inject(s|ing)? (arbitrary )?(code|php|script)", I), "F5", "Code injection / eval / template injection"),
    (re.compile(r"shell metachar|command injection|os command|crafted command|command[- ]line (argument|option|parameter)|command parameter", I), "F5", "OS command / argument injection"),
    (re.compile(r"inject", I), "F5", "Injection (generic)"),
    (re.compile(r"(do(es)? not|without|no|lacks?|missing|fail(s|ed)? to) (require|check|perform|enforce)?\s*(any )?authenticat|unauthenticated|authentication bypass|bypass(es|ing)? authentication|improper authentication", I), "F9", "Missing or improper authentication"),
    (re.compile(r"authoriz|access control|permission", I), "F9", "Access control (generic)"),
    (re.compile(r"race condition|\btoctou\b|time-of-check", I), "F6", "Race condition"),
    (re.compile(r"hard-?coded|default (password|credential)", I), "F8", "Hard-coded or default credentials / keys"),
    (re.compile(r"certificate", I), "F8", "Certificate / TLS validation"),
    (re.compile(r"logic (issue|error|flaw)|business logic", I), "F12", "Incorrect control flow or logic"),
    (re.compile(r"input validation|validation issue|improper(ly)? validat|insufficient validation|does not (properly )?validate", I), "F5", "Generic improper input validation"),
]
PROMPT_INJECTION = re.compile(r"prompt injection|indirect prompt", I)
PROMPT_INJECTION_CWES = {"CWE-1427", "CWE-1426"}
PROMPT_SUBCAT = "Prompt injection / AI agent manipulation"
