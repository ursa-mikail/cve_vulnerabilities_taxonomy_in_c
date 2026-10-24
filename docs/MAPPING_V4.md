# Mapping v3 -> v4: what was wrong, what changed, how it was checked

The v3 mapping put every CVE in one family. Auditing it against the CWE definitions and against famous CVEs
(Heartbleed, Shellshock, Log4Shell, ...) found systematic errors. v4 fixes the ones that could be fixed with
evidence and **leaves a documented residue**. Every change is listed row by row in
`repair_changelog_v3_to_v4.csv`; `v3_family_id` and `repair_rule` columns in the v4 CSV let you revert any of them.

## Rules (see `tools/mapping_rules.py`)

| Rule | Rows | Problem found | Fix |
|---|---:|---|---|
| R1 CWE override | 589 | A CWE inherited the family of an over-general ancestor. CWE-134 (format string, 415 CVEs) was filed under **access control** via CWE-668; CWE-591, 226, 244, 402, 837 had similar inheritance errors. | Explicit family per CWE (format string -> F5, residual-data CWEs -> F10, ...). |
| R2 Umbrella refinement reverted | 3,110 | Umbrella CWEs (CWE-119, 74/77, 264, 284, 693, ...) were "refined" into other families by **impact** words ("denial of service", "execute arbitrary code"), e.g. command injection filed as memory corruption. | Keep the refinement only if the description names that family's weakness; otherwise return to the CWE's own family. |
| R2b CWE-20 memory label | 808 | CWE-20 (input validation) placed in memory-safety families with no memory evidence. | Re-read description; else F5 "Generic improper input validation". |
| R3 Unsupported memory label | 2,517 | 10,937 rows were "Memory corruption (unspecified)" with no CWE; ~4,300 had no memory word at all. Struts OGNL injection (CVE-2018-11776) and PHP-CGI argument injection (CVE-2012-1823) were filed as memory bugs. | If the text names a specific weakness, use it (injection, authentication, logic, race...). Otherwise **U0 Unclassified** with `best_guess_family = F5` (see below). 432 rows re-labelled, 2,085 to U0. |
| R4 Format-string wording | 119 | "Format string" text with no CWE sat in F1. | -> F5 "Format string injection". |
| R5 Prompt-injection subcategory | 141 | AI/agent prompt injection had no visible subcategory. | Subcategory "Prompt injection / AI agent manipulation" inside F5. |

Total touched: 7,284 rows; 7,143 changed family. Unchanged rows are byte-identical to v3 (verified).

## Why U0 and why best guess F5

Among CVEs that have a *specific* CWE and the same impact-only wording ("execute arbitrary code", no weakness
named), about **56% are injection (F5) and 21% memory (F1-F4)**. The v3 "memory" label was therefore wrong about
four times in five. Such records belong in U0; their `best_guess_family` is F5 as a base-rate prior, kept out of
all counts. Counter-example: EternalBlue (CVE-2017-0144) *is* a memory bug, but its public text does not say so,
so a text-based mapping cannot know.

## What was deliberately NOT changed

* **CWE-20, CWE-189, CWE-310** keep their wording-based refinements. They have no single right home, and
  sampled refinements (e.g. CWE-310 hash-collision CPU exhaustion -> F7) were correct.
* **DoS-only wording -> F7** stays: F7 is defined as availability.
* Many rows rest on the CWE the NVD/CNA assigned, which is sometimes itself wrong (CVE-2017-5638 is OGNL injection
  but carries CWE-755). The mapping follows the CWE and marks it high confidence.

## Residual uncertainty (measured)

79.3% of classified CVEs rest on a specific CWE. 36,071 (9.7%) rest on an umbrella CWE refined by wording
(`medium`), 35,930 (9.6%) on description keywords (mostly `low`), and 5,214 on the Linux-title heuristic, the
text classifier or hierarchy inheritance. Precision of the non-CWE bases has not been measured against a hand-labelled set.

## How it was checked

* Row count, unique IDs and column order preserved; non-repaired rows identical to v3.
* Precision sampled for every rule (5-10 random changed rows each, read by hand); the ladder was extended after the
  R3 sample exposed "logic issue" wording falling to U0.
* `tools/build_analytics.py` reproduces every figure in the shipped v3 `analytics.json` except one tie ordering,
  so the v4 dashboard is a pure function of the CSV.
