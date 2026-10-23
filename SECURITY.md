# Security model of this lab

This project runs attacker-style C code (intentionally vulnerable snippets) to demonstrate
real bugs. Read this before exposing it beyond `localhost`.

## What is protected, and how

| Protection | Where | What it stops |
|---|---|---|
| Only pre-written, reviewed C files are compiled | backend, by design | No arbitrary code execution via the API — the `demo id` selects one of a fixed set of files on disk; nothing from the request body is ever written to a file or compiled |
| Non-root execution | `backend/Dockerfile` runs as the built-in `node` user (uid 1000) | A compiled demo binary cannot touch root-owned files or escalate |
| Read-only root filesystem + tiny tmpfs | `docker-compose.yml` (`read_only: true`, `tmpfs: /tmp`) | Nothing persists between runs; nothing outside `/tmp` can be written at all |
| `cap_drop: ALL`, `no-new-privileges` | `docker-compose.yml` | Removes every Linux capability the backend container doesn't need; blocks privilege-escalating binaries |
| `pids_limit`, `mem_limit`, `cpus` | `docker-compose.yml` | Caps the whole backend container's resource use, so a runaway demo can't take down the host |
| `ulimit -v` per run | `backend/runner.js` | Caps the **individual demo process's** virtual memory, independent of the container limit, so `malloc`-heavy demos (see F7) fail cleanly and fast instead of pressuring the whole container |
| `timeout -k` per run | `backend/runner.js` | Hard wall-clock limit per demo process; infinite loops or hangs are killed automatically |
| No outbound network needed by demos | demos don't call out | Nothing a demo does can exfiltrate data or reach the internet |
| Output capped in size | `backend/runner.js` | A demo that floods stdout can't exhaust the Node process's memory |

## What this is **not**

- **Not a hardened multi-tenant sandbox.** It is still a single Docker container on the shared
  host kernel — a kernel-level container-escape vulnerability would still apply, exactly as it
  would to any other container. Do not expose this to the open internet or to untrusted users
  without adding a real isolation layer (gVisor, Firecracker/microVMs, or similar).
- **Not an arbitrary code runner.** The API only ever compiles the 28 fixed files that ship in
  `backend/demos/`. There is no endpoint that accepts C source from a request.
- **Not guaranteed to reproduce every bug identically on every machine.** Timing-dependent
  demos (the race condition, F6) are inherently non-deterministic; that's explained in the UI.

## Intended use

Local learning and teaching, on `localhost`, by one user at a time. That is the threat model
this lab was built for.
