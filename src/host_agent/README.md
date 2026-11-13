# DFIR VAO Host Agent (Windows)

One EXE for the Windows PC whose NVIDIA cards run the AI for the DFIR VM.

* **Install / repair**: reads the GPUs (nvidia-smi), picks the profile the Linux installer would pick
  (tiny test / small / medium / large), downloads the newest llama.cpp CUDA 12.4 build and llama-swap
  from GitHub (SHA-256 from the release metadata checked) and the GGUF models from Hugging Face
  (SHA-256 of the LFS object checked). Every file goes to `provenance.jsonl`.
* **One port for the VM** (default 1234): a reverse proxy in front of llama-swap (which listens on
  127.0.0.1 only). It wants the agent token (`Authorization: Bearer ...`), queues inference
  requests (at most `Parallel` at once), answers `/agent/hello` without a token (the VM installer
  finds the agent by itself) and `/agent/status` with it (GPUs, queue, versions, loaded models).
* **Firewall** (administrator): the port opens only for the VMware / Hyper-V / VirtualBox subnets.
* **Autostart**: administrator = task at Windows start as SYSTEM; otherwise at user logon (HKCU Run).
* **Update**: new build into a side folder → trial run (`--version`) → switch → one real model
  answer → otherwise back to the previous build (kept on disk).

Files live in `%ProgramData%\DFIR_VAO_Agent` (agent.json with the token is closed to other users).

Build: `powershell -ExecutionPolicy Bypass -File src\host_agent\make_agent.ps1 -Out out`
(.NET Framework csc, nothing to install).

CLI (no arguments = window): `--detect --plan --gen-config OUT --install [--no-models] --serve
--status --hello --check-update --update [--from-zip ZIP] --autostart on|off --token show|new`,
options `--home DIR --port N --swap-port N --profile auto|tiny|small|medium|large --parallel N
--fake-gpus 16,16 --lang en|uk --task-name NAME --gui-shot PNG`.

## Tests
* `test_config_parity.ps1 -Exe out\DFIR_VAO_Host_Agent.exe -Ps1 infra\host\setup_llm_host.ps1`:
  config.yaml of the agent is line-for-line the one of the PowerShell setup for 8 card sets.
* `test_update.ps1 -Exe ... -AgentHome <test home with a serving agent>`: archive without
  llama-server refused; a build that cannot serve rolled back; a good build switched to and answers;
  the previous build is kept.
* `test_host_agent_vm.py` (run in the VM, `AGENT_URL`, `AGENT_TOKEN`, agent with `--parallel 1`):
  hello without token, 401 without / with a wrong token, models, answer, streaming, `/running`,
  4 requests at once queue behind 1, status counters.
