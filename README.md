# CVE Vulnerability Taxonomy

An interactive, self-contained lab for the 14-family C vulnerability taxonomy. Browse the
taxonomy tree, open any demo, and run the **vulnerable** and **fixed** versions of real C code
side by side — each one compiled and executed live, in a sandboxed container, with
AddressSanitizer / UndefinedBehaviorSanitizer / ThreadSanitizer catching the bug as it happens.

![main](main.png)

## Quick start

Requires Docker and Docker Compose (the `docker compose` plugin, not the old `docker-compose`
standalone).

```bash
./up      # builds and starts everything, prints the address when ready
./down    # stops the lab (keeps images, fast restart)
./clean   # stops everything and deletes containers, volumes and images
./logs    # watch live logs (Ctrl+C to exit)
```

(`make up`, `make down`, `make clean` still work too.)

Then open **http://localhost:8080**.

## Analytics tab

The top bar's **Analytics** link opens a dashboard built from the real CVE Program record set
(412,863 CVEs, 1999&ndash;2026, enriched with NVD's CWE and CVSS data) mapped onto these same
14 families, plus two bookkeeping buckets (`U0` unclassified, `R0` rejected/withdrawn):

- KPI cards (total, published, rejected, unclassified, years covered)
- A bar chart of CVE counts per family &mdash; hover for the exact count, click to drill into that
  family's top CWEs, top subcategories, and example CVEs (with a link to the live demo above it,
  if one exists)
- An interactive multi-line trend chart (the 5 largest families + the running total, 1999&ndash;2026)
  with a hover crosshair showing exact per-year counts for every series at once
- A severity donut (CVSS Critical/High/Medium/Low)
- Ranked lists of the most-affected vendors and products

The data lives in `backend/analytics/analytics.json`, built once offline from the full CVE
dataset and shipped with the image — the dashboard needs no internet access at runtime.

### How complete is the CVE mapping?

- **Every CVE record in the dataset appears exactly once** (412,863 rows, no duplicates, no empty descriptions).
- Each CVE is mapped to one family by its CWE (NVD/CNA) where available, otherwise by description keywords.
- **19,693 (4.8%) are `U0` Unclassified**: the public record does not say what kind of weakness it is.
  About 7,600 are vendor advisories (mostly Oracle patch bulletins) whose text names no weakness at all,
  so they cannot honestly be classified. The rest are too vague for the classifier to be confident; the CSV
  gives a `best_guess_family` for those, kept out of the counts. Nothing is dropped.
- **18,629 are `R0` Rejected/Withdrawn** CVE IDs.
- Check the `mapping_confidence` column (`high` / `medium` / `low`) before relying on a single row:
  keyword-based and heuristic rows are `low`. 1,612 Linux kernel CVEs were recovered from the commit
  title with keyword rules, and 2,076 more by a text classifier trained on CVEs that do have a CWE
  (about 88% accurate on a held-out test of CVEs with clear descriptions, lower on vague ones). All of these
  are marked `low` and are estimates.
- The dataset is a snapshot: CVEs published after it was built are not included.

## How to navigate (you will never be lost)

- **Left sidebar**: the full taxonomy tree, families F1–F14, each expandable to its demo(s).
  The demo you're viewing is always highlighted.
- **Top bar**: a permanent link back to Home from anywhere, plus "How this works".
- **Breadcrumb**: every demo page shows `Family · Subcategory` above its title.
- **Prev / Next**: linear walkthrough buttons at the bottom of every demo, so you can click
  through all 14 families in order without touching the sidebar.
- **URLs are shareable**: every demo has its own `#/demo/<id>` address — bookmark it, send it,
  or use the browser's back/forward buttons; they all work normally.
- If a demo ID doesn't exist (bad link, old bookmark), the page says so plainly and links home
  instead of showing a blank screen.

## What "run in sandbox" actually does

1. The backend compiles **one of a fixed set of C files that ship with this repo** —
   never code typed into the browser — with `-fsanitize=address,undefined` (or `thread` for
   the concurrency demo).
2. It runs the resulting binary as a non-root user, with no network access, a capped virtual
   memory limit, a process-count limit, and a hard timeout.
3. stdout, stderr, the sanitizer's report (if any), the exit code, and the timing come back and
   are shown next to the code.

See `SECURITY.md` for the full list of protections and their honest limitations.

## Project layout

```
cve-lab/
  up down clean logs       one-word launcher scripts
  Makefile                 same commands via make
  docker-compose.yml       backend + frontend services, resource limits
  backend/                 Node/Express API that compiles & runs the demos
    demos/<id>/
      meta.json            title, CWE, root cause, defenses, compiler flags
      vulnerable.c
      fixed.c
  frontend/                React (Vite) single-page app, served by nginx
```

## Adding a new demo

1. Make a new folder under `backend/demos/<your-id>/`.
2. Add `vulnerable.c` and `fixed.c` — each a small, self-contained `main()` that prints what
   it's doing in plain language (the UI shows stdout directly).
3. Add `meta.json`:

```json
{
  "family": "F1",
  "family_name": "Spatial Memory Safety",
  "subcategory": "Stack-based buffer overflow",
  "cwe": "CWE-121",
  "title": "Stack buffer overflow via strcpy",
  "root_cause": "One sentence explaining the broken invariant.",
  "defenses": ["Concrete defense 1", "Concrete defense 2"],
  "sanitize": "address,undefined",
  "extra_cflags": [],
  "ulimit_v_kb": 262144,
  "timeout_s": 5
}
```

4. Restart with `./up`. The backend scans the `demos/` folder on startup, so the new demo
   appears in the tree automatically — no other file needs editing.

## Troubleshooting

- **`useradd: UID 1000 is not unique`**: fixed in this version. The `node:20-slim` base image already
  includes a non-root `node` user (UID 1000), so the backend now reuses it instead of creating a new one.
  If you still see this error, you are building from an older copy of `backend/Dockerfile`.
- **"Could not reach the backend" in the browser**: fixed in this version (the proxy was dropping the `/api` prefix). Run `./clean` then `./up` so the images are rebuilt.
- **Port 8080 already in use**: edit the `ports:` line under `frontend` in `docker-compose.yml`.
- **`./up` fails to build**: run `./logs`; the most common cause is no internet access
  during the Docker build (both images install packages from the network).
- **A demo times out instead of showing a clean result**: that is often the point (see the
  resource-exhaustion demo, F7) — the sandbox's limits are working as intended.
