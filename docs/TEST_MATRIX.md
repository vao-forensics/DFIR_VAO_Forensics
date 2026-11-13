# Test matrix "from scratch" (T8)

Every cell = a **brand-new** incus container from a stock distro image → the repository copied in
exactly as it is published (`tools/export_github.py`) → `./install.sh --answers <file>` with no
human input → checks. Nothing is reused between cells; the container is deleted after the cell.

## How to run

On a machine with incus (our test host is the DFIR VM):

```bash
# images once: incus image copy images:ubuntu/22.04 local: --alias t8-jammy   (noble, debian/12 = t8-bookworm)
bash installer/guest/t8/t8_matrix.sh                 # all cells, one after another
bash installer/guest/t8/t8_matrix.sh noble-cloud     # one cell
cat var/t8/summary.txt                               # one result line per cell; full logs var/t8/<cell>.log
```

A cell **passes** only if all three hold:
1. `install.sh` exits 0;
2. `installer/guest/verify_install.sh` — every check PASS (containers healthy, bot, Open WebUI,
   sandbox, enabled/disabled modules, …);
3. one real chat completion through the bot's own LLM endpoint (`172.17.0.1:1234` from
   `case-maintainer`) returns the expected answer — i.e. the chosen AI really answers.

The Telegram token in every answers file is a stub (`100000001:STUB_…`) served by
`installer/guest/test_tg_stub.py` — a test must never use the working bot's token.

## Cells

| Cell | OS | AI mode | What is behind it |
|---|---|---|---|
| jammy-server | Ubuntu 22.04 | own server / DFIR Host Agent | llama-swap on the Windows host |
| noble-server | Ubuntu 24.04 | own server / DFIR Host Agent | same |
| bookworm-server | Debian 12 | own server / DFIR Host Agent | same |
| noble-cloud | Ubuntu 24.04 | cloud provider (`custom`, API key) | `cloud_standin.py`: demands `Bearer <key>` (401 otherwise), forwards to llama-swap; the line shows how many requests came with the key and how many were refused |

Answers files: `installer/guest/t8/answers_server.env`, `answers_cloud.env`
(cloud cell also switches modules off: `webchat hashdb translate bookidx`, so the "module off" checks run too).

## What this matrix does NOT cover (honestly)

* **Local GPUs inside the guest** (`LLM_MODE=local`): a container has no GPU, so the NVIDIA runtime,
  model download and llama-swap-in-guest path cannot be tested here. It is tested only on real
  hardware (the production rig) — a cell needs a machine with an NVIDIA card or GPU passthrough.
* **Real cloud providers** (OpenAI, Gemini, OpenRouter): no paid key is used in tests; the
  stand-in reproduces the provider contract (OpenAI-compatible API + mandatory key), not the provider.
* The Windows side (VM wizard, Host Agent, Builder) has its own E2E tests (T5, T7).

## Results

See the table appended below by the last run (date, repo commit, per-cell line).

### Run 2026-11-13 (evening), after the web-portal install step — PASS

| Cell | OS | install | verify_install | real LLM answer | note |
|---|---|---|---|---|---|
| noble-server | ubuntu-24.04 | rc=0 (52 min) | 24/24 | ok | new checks: personal-sandbox gateway, egress rules, tool server, 6 portal functions, nightly timers |

### Run 2026-11-13 (morning) — 4/4 PASS

| Cell | OS | install | verify_install | real LLM answer | note |
|---|---|---|---|---|---|
| jammy-server | ubuntu-22.04 | rc=0 | 13/13 | ok | |
| bookworm-server | debian-12 | rc=0 | 13/13 | ok | |
| noble-server | ubuntu-24.04 | rc=0 | 13/13 | ok | |
| noble-cloud | ubuntu-24.04 | rc=0 | 13/13 | ok | stand-in: 8 requests with the key, 0 refused |

Defects this matrix found and fixed before the green run:
* the Telegram stub ran inside the guest only when python3 was present -> Debian 12 (no python3 before
  install.sh) failed at the token check. The stub now runs on the test host.
* unattended install: a failed LLM test request (model busy) made the installer pick "change", wipe the
  given API key and stop with a misleading "LLM_API_KEY is not set". Now it keeps the answers, warns and
  goes on; verified live with a busy LLM: install rc=0, 13/13.
* the shared host GPUs: a model benchmark holding llama-swap times every LLM call out; the runner now
  waits for `state/bench_active` to clear.
