# CVE Weakness Taxonomy Lab

An interactive, self-contained lab for a **14-family taxonomy of weaknesses that covers the whole CVE
record** (412,863 CVE IDs). A family is a root-cause idea -- "untrusted data is interpreted as a command",
"a limit is not enforced", "the code does not check who is allowed" -- so it applies to every language and
every kind of system, not to C. The demos are small, runnable illustrations of each idea. They are written
in **C, JavaScript (Node.js) and Python** because the weaknesses show up in all of them; the language of a
demo is incidental, and each demo says which one it uses.

Browse the taxonomy, open any demo, and run the **vulnerable** and **fixed** versions side by side in a
sandboxed container. C demos run under AddressSanitizer / UndefinedBehaviorSanitizer / ThreadSanitizer;
the others print `[ATTACK SUCCEEDED]` or `[BLOCKED]` so non-crashing bugs (injection, logic, access
control, supply chain) are just as visible as memory corruption.

![main](main.png)

## Quick start

Requires Docker and Docker Compose (the `docker compose` plugin, not the old `docker-compose` standalone).

```bash
./up      # builds and starts everything, prints the address when ready
./down    # stops the lab (keeps images, fast restart)
./clean   # stops everything and deletes containers, volumes and images
./logs    # watch live logs (Ctrl+C to exit)
```

(`make up`, `make down`, `make clean` still work too.) Then open **http://localhost:8080**.

## The tabs

- **Home**: the 14 families, where each one shows up (languages, ecosystems, device types), real CVEs
  that exemplify it, and a table showing that *domains* (web, native, mobile, cloud, IoT/ICS, AI,
  supply chain) cut across families.
- **Analytics**: counts per family over time, by severity, vendor and product, with drill-down.
- **Explore**: filter all CVEs by **operating system**, **programming language**, **system type**,
  weakness family, year range, minimum severity and evidence strength. Chips show live counts; results
  show the families, most common subcategories (each linked to a runnable demo when one exists), top
  CWEs, vendors, trend, severity and a stable sample of matching CVEs. Filters are URL-shareable
  (`#/explore?os=linux&lang=c_cpp&family=F1,F2`).
- **Coverage**: "does this cover all of CVE?" answered with data: every subcategory in the record, its
  size, how strong the evidence behind it is, whether a demo covers it, and a crosswalk to MITRE's ten
  top-level CWE pillars.

### How the Explore filters work (read this before quoting a number)

The CVE record has no "operating system" or "language" field. These facets are **inferred** from vendor,
product, assigner and description wording (plus short hand-written lists such as WordPress -> PHP). The
rules are in `tools/facet_rules.py`; nothing is guessed for a CVE that names nothing. Measured coverage:
about **19%** of records name an operating system, **39%** point at a programming language and **69%** fit
a system type, so a filter can only see the records that say something. A value like "PHP" means *the
record points at PHP code*; wording-based rules also have false positives (a description that merely
mentions a browser is counted as "browser"). One CVE can carry several values per group. Counts were
cross-checked against an independent recomputation.

### How complete is the CVE mapping?

- **Every CVE record appears exactly once** (412,863 rows, no duplicates, no empty descriptions).
- Each CVE is mapped to one family by its CWE (NVD/CNA) where available, otherwise by description
  keywords. **79%** of the 372,456 classified CVEs were placed by a *specific* CWE (high confidence).
  The weaker bases (umbrella CWEs refined by wording, keywords, hierarchy inheritance, a text classifier,
  Linux commit titles) are marked `medium` or `low` in `mapping_confidence`; the Coverage tab shows the split.
- **21,778 (5.3%) are `U0` Unclassified**: the public text names no weakness. 7,599 are vendor advisories
  (mostly Oracle bulletins), 12,094 are too vague for the classifier, and 2,085 were moved here by the v4
  repair because they were labelled "memory corruption" only on the strength of the phrase "execute arbitrary
  code", which is an impact, not a weakness (CVEs with a specific CWE and the same wording are ~56% injection
  and only ~21% memory bugs). The CSV gives a `best_guess_family` for U0 rows, kept out of the counts.
- **18,629 are `R0` Rejected/Withdrawn** CVE IDs.
- 1,612 Linux-kernel CVEs were recovered from the commit title and 2,076 more by a text classifier
  (about 88% accurate on a held-out set of clear descriptions, lower on vague ones); all are `low`.
- The dataset is a snapshot: later CVEs are not included.
- **What "covered by a demo" means**: 14 of 14 families and 26 of 95 subcategories (about 53% of classified
  CVEs) have a runnable demo. The rest are listed on the Coverage tab as "no demo yet" rather than hidden.

## Data and tooling (`tools/`)

Everything shipped in the dashboard can be rebuilt from the mapping CSV:

```bash
python3 tools/repair_mapping.py  cve_family_mapping_v3.csv cve_family_mapping_v4.csv repair_changelog_v3_to_v4.csv
python3 tools/build_analytics.py cve_family_mapping_v4.csv backend/analytics/analytics.json
(cd tools && npm install) && python3 tools/build_facets.py cve_family_mapping_v4.csv backend/analytics
```

`docs/MAPPING_V4.md` explains what the v3 -> v4 repair changed and why; `repair_changelog_v3_to_v4.csv`
lists every changed row (7,284) so any change can be audited or reverted. `backend/taxonomy.json` is the single
source of truth for family names, definitions and cross-language notes.

## Tests

```bash
cd backend && npm test                        # all 27 demos: the bug appears, the fix holds
cd backend && PORT=4010 node server.js &      # then:
cd frontend && npm test                       # renders Home / Explore / Coverage / a demo against the live API
```

## How to navigate (you will never be lost)

- **Left sidebar**: the full taxonomy tree, families F1-F14, each expandable to its demos (with language tags).
  The demo you're viewing is always highlighted.
- **Top bar**: permanent links to Home, Analytics, Explore, Coverage and "How this works".
- **Breadcrumb**: every demo page shows `Family . Subcategory` above its title.
- **Prev / Next**: linear walkthrough buttons at the bottom of every demo.
- **URLs are shareable**: every demo and every filter has its own `#/...` address.
- If a demo ID doesn't exist, the page says so plainly and links home instead of showing a blank screen.

## What "run in sandbox" actually does

1. The backend picks **one of a fixed set of demo files that ship with this repo** (C, JavaScript or
   Python), never code typed into the browser. C files are compiled with `-fsanitize=address,undefined`
   (or `thread` for the concurrency demo); JavaScript and Python files run directly.
2. It runs the program as a non-root user with a hard timeout and a process limit (and, for C, a capped
   virtual-memory limit). The backend container is on an internal Docker network with no route to the internet.
3. stdout, stderr, the sanitizer's report (if any), the `[ATTACK SUCCEEDED]` / `[BLOCKED]` verdict, the
   exit code and the timing come back and are shown next to the code.

See `SECURITY.md` for the full list of protections and their honest limitations.

## Project layout

```
cve-lab/
  up down clean logs       one-word launcher scripts
  Makefile                 same commands via make
  docker-compose.yml       backend + frontend services, resource limits, internal network
  backend/                 Node/Express API that runs the demos and serves the data
    taxonomy.json          single source of truth: families, definitions, domains, CWE pillars
    runner.js              runs C (sanitizers), JavaScript (node) and Python (python3) demos
    facets.js              live OS / language / system-type filtering
    test_demos.js          asserts every demo's bug appears and its fix holds
    demos/<id>/
      meta.json            title, language, CWE, CVE-data subcategory, root cause, defenses, expectations
      vulnerable.<c|js|py>
      fixed.<c|js|py>
    analytics/             analytics.json, facets.bin.gz, facets.meta.json (built by tools/)
  frontend/                React (Vite) single-page app, served by nginx; `npm test` = render tests
  tools/                   repair_mapping.py, build_analytics.py, build_facets.py + their rules
  docs/MAPPING_V4.md       what the v3 -> v4 repair changed, and how it was checked
```

## Adding a new demo

1. Make a new folder under `backend/demos/<your-id>/`.
2. Add `vulnerable.<ext>` and `fixed.<ext>` (`c`, `js` or `py`). Each is a small, self-contained program
   that prints what it is doing in plain language. For non-crashing bugs, print `[ATTACK SUCCEEDED]` in
   the vulnerable version and `[BLOCKED]` in the fixed one.
3. Add `meta.json`. `csv_subcategory` must be an existing subcategory name from the Coverage tab, so the
   demo links to the CVEs it illustrates; `expect` tells `npm test` what to look for (`"SANITIZER"` for C
   demos that trip a sanitizer, `"VERDICT"` for the markers above, or a regular expression):

```json
{
  "family": "F5",
  "family_name": "Injection and Input Interpretation",
  "language": "python",
  "subcategory": "SQL injection",
  "csv_subcategory": "SQL injection",
  "cwe": "CWE-89",
  "title": "SQL injection through string-built queries",
  "root_cause": "One sentence explaining the broken invariant.",
  "defenses": ["Concrete defense 1", "Concrete defense 2"],
  "expect": { "vulnerable": "VERDICT", "fixed": "VERDICT" },
  "timeout_s": 5
}
```

4. Run `cd backend && npm test`.
