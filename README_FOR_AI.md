# AI_HELPER — full guide for an AI assistant installing or fixing DFIR Bot

You are an AI assistant (ChatGPT, Gemini, a local model...) helping a person install, check or
repair **DFIR Bot** on their own server. This file is your manual. Read it fully before acting.
The person may not be technical: explain simply, one step at a time, in their language.

## 0. Rules you must follow

1. **Never ask for, print or paste secrets** (Telegram token, passwords, API keys, private keys) into the
   chat. If you need to check a value, ask the person to run a command that tests it, not to show it.
2. **Never upload case data** (evidence archives, reports, `cases/`, `state/`) anywhere.
3. Do not invent missing facts. If a command's output is needed, ask the person to run it and paste it.
4. Prefer the project's own tools (`install.sh`, `dfir ...`) over manual changes. They are idempotent.
5. Before deleting or overwriting anything, say what and why, and get a "yes".

## 0a. If you are an AI agent with a terminal (Codex, Aider...)

1. Check: Ubuntu 22.04 / 24.04 or Debian 12, and `sudo` works.
2. Clone the repository and run `sudo ./install.sh`.
3. **Ask the person to answer the questions themselves.** Tokens, keys and passwords are typed into hidden fields:
   you must not see, repeat or store them.
4. If a step fails, read `state/install.log` (it holds no secrets), fix the cause using the troubleshooting table
   below, then run `sudo ./install.sh` again: it continues where it stopped.
5. At the end, remind the person to open `~/DFIR_VAO_credentials.txt`, move the passwords to a password manager
   and delete the file.
6. Check the result: `sudo dfir status`.

## 1. What the system is

```
Windows PC under investigation                 Linux server (Ubuntu 22.04/24.04, Debian 12)
DFIR_Collector.exe  --encrypted archive-->     Docker: n8n (Telegram logic), case-maintainer (parse+analysis),
(built by DFIR_VAO_Collector_Builder_v1.0.exe)          logdb (PostgreSQL), qdrant, webhook-gate (+ngrok), llm-gw,
                                               tools-sidecar, tg-i18n, Open WebUI (browser chat), sandbox
                                                       |
                                                       v  http://172.17.0.1:1234 (OpenAI-compatible)
                                               llama-swap (local NVIDIA GPUs) or llm-router (other server/cloud)
```

* Reports come to the owner in **Telegram**. The browser chat (**Open WebUI**, port 3000) lets people
  attach files; each attached file is analysed in an **isolated sandbox** (container without network,
  user nobody, read-only, CPU/RAM/time limits, archive-bomb caps) and the model gets the result.
* Collector archives are encrypted for one server. They are decrypted only in the trusted
  `case-maintainer` container; the private key never enters the sandbox.
* Project folder is always reachable as **`/srv/dfir`** (the installer links a clone made elsewhere).

## 2a. Pick the scenario first (ask the person, then follow ONE row)

| Where the server runs | Where the GPUs are | Answer at "AI" | What to do |
|---|---|---|---|
| Ubuntu/Debian on a real PC | NVIDIA cards in the same PC | `local` | Installer detects the cards (`installer/detect_hw.sh`). No/old driver -> it offers `ubuntu-drivers install` + one reboot; re-run `sudo ./install.sh`, the answers are kept. Check: `nvidia-smi` lists every card |
| Ubuntu VM in VMware / Hyper-V / VirtualBox on Windows | NVIDIA cards in the Windows host | `server` | A VM does not see the host GPUs. On Windows run **`DFIR_VAO_Host_Agent.exe`** (Releases) as admin: it checks the driver, picks a model set from the VRAM, installs llama.cpp + llama-swap with SHA-256 checks and serves an OpenAI-compatible API with a token. Give the VM the host address shown by the agent (VMware NAT: usually `192.168.<x>.1:1234`) and the token. Windows firewall must allow TCP 1234 from the VM network |
| Ubuntu in WSL2 | cards in Windows | `local` | WSL uses the Windows driver: do NOT install a driver inside WSL (installer says so). `nvidia-smi` inside WSL must work first |
| Any Linux server | GPUs in ANOTHER PC (office, home) | `server` | Run the Host Agent on that PC (Windows) or any OpenAI-compatible server (llama-swap, LM Studio, Ollama with `/v1`). Connect the two machines over VPN (WireGuard or ZeroTier, below) and give the VPN address of the GPU PC |
| Any Linux server | no GPU | `cloud` | Provider + API key: OpenAI, Anthropic, Gemini, OpenRouter, Groq, Mistral, DeepSeek or a custom OpenAI-compatible URL. The installer warns that evidence text then leaves the server and asks to confirm |

VPN (question 7) — how people reach the portal from outside; Telegram does not need it (it uses ngrok):

| Choice | When | What the person does |
|---|---|---|
| `wireguard` | the server has a public ("white") IP or DynDNS and the router can forward UDP 51820 | nothing else; installer creates the server and a phone config + QR (`state/wireguard/owner.conf`) |
| `zerotier` | no public IP, or the router cannot forward ports | create a free network at my.zerotier.com, copy the 16-character Network ID; during install tick **Auth** for this server in Members. Phones/laptops install the ZeroTier app and join the same ID. Can be slower when traffic goes through ZeroTier relays |
| `none` | only inside the local network | — |

## 2. Install from zero (what the person does)

```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/vao-forensics/DFIR_VAO_Forensics.git
cd DFIR_VAO_Forensics
sudo ./install.sh
```

The installer is interactive. Answers are saved in `state/install_answers.env` (secret, mode 600), so a
re-run continues where it stopped. At **any** question the person can type `?` for an explanation.

Questions, in order:

| # | Question | What to answer / where to get it |
|---|---|---|
| 1 | Language | any; the rest of the installer speaks it |
| 2 | AI: `local` / `server` / `cloud` | `local` = NVIDIA cards in this box (driver installed automatically, one reboot); `server` = cards in another PC (e.g. Windows host with this server in a VM: run `DFIR_VAO_Host_LLM_Setup.ps1 (GitHub Releases)` there as admin, give its address); `cloud` = provider + API key (evidence leaves the server, installer asks to confirm) |
| 3 | Profile (local) | suggested from VRAM: small / medium / large |
| 4 | Telegram bot token | @BotFather -> /newbot -> copy token. The installer checks it (getMe) |
| 5 | Owner chat | the person sends `/start` to their new bot; the installer finds the chat_id itself |
| 6 | Webhook | `ngrok` (free): 1) sign up at https://dashboard.ngrok.com/signup, 2) left menu "Your Authtoken" -> Copy, 3) left menu "Domains" -> "+ New Domain" (one free `*.ngrok-free.app`). The installer shows these steps and runs ngrok itself. Or `url`: your own HTTPS reverse proxy to port 8099 |
| 7 | VPN: `wireguard` / `zerotier` / `none` | see 2a. WireGuard creates server + phone config with QR; ZeroTier asks the Network ID and waits until the server is authorised |
| 8 | Bot language | default language of the bot |
| 9 | **Logins and passwords** | Open WebUI admin e-mail + password, pgAdmin e-mail + password, PostgreSQL password. **Enter at a password = strong generated one.** Own passwords need 10+ characters, typed twice |
| 10 | Review screen | shows everything; change any part or install |

Then the install steps run (`installer/apply.sh`, `APPLY_STEPS`):

| Step | What it does | How to verify |
|---|---|---|
| consent | (before the questions) shows the software list with licences and the AGPL-3.0 agreement; nothing happens without "yes"; recorded in `state/consent.txt` | `cat state/consent.txt` |
| pathlink | links the clone to `/srv/dfir` (refuses if an unrelated `/srv/dfir` exists) | `readlink -f /srv/dfir` |
| prereqs | Docker + compose, NVIDIA container toolkit if needed | `docker compose version` |
| seal_keys | collector key pair in `state/keys/` (back up `collector_private.pem`!) | file exists, mode 600 |
| models | downloads GGUF models for the profile | `ls models/` or the AI server |
| llm | llama-swap / llm-router on 172.17.0.1:1234 | `curl -s http://172.17.0.1:1234/v1/models` |
| env | writes `.env` (600) and fills `CHANGE_ME_*` placeholders listed in `CHANGE_ME_FILES.txt` | `grep -rl CHANGE_ME_ --exclude=CHANGE_ME_FILES.txt .` should list nothing important |
| zerotier | joins the ZeroTier network (if chosen), waits for Auth, bot links use the ZeroTier IP | `zerotier-cli listnetworks` shows OK + an IP |
| wireguard | VPN (if chosen) | `wg show` |
| docker | `docker volume create open-webui` + `docker compose up -d --build` | `docker ps` all Up/healthy |
| dbroles | read-only database role `dfir_mcp` for agents (no access to user, access or chat-log tables) | `docker logs llm-gw` shows no auth errors |
| n8n | imports credentials + workflows, activates them | `docker exec n8n n8n list:workflow` |
| webui | waits for Open WebUI, installs hourly 24 h upload deletion (`owui-retention.timer`) | `curl -s localhost:3000/health`; `systemctl status owui-retention.timer` |
| sandbox | builds `dfir-sandbox:0.1`, starts `dfir-sandbox-api` on the Docker bridge gateway :8791 with a token, installs the Open WebUI filter `dfir_files` | `systemctl status dfir-sandbox-api`; in Open WebUI: Admin > Functions shows "DFIR" filter active+global |
| portal | personal sandboxes (`usandbox-net` 172.30/16, internet ONLY via tinyproxy allow-list: pip, GitHub, apt; everything else dropped in `DOCKER-USER`), Open WebUI functions (model dispatcher, assistant identity, per-user profile, live model status, skills, storage table), sandbox tool server, nightly model sync / skill learning / backup / profiles, 12-min self-check | `sudo bash installer/guest/verify_install.sh` (portal lines PASS); `systemctl list-timers 'dfir-*'` |
| genlang | only if "Other language" was chosen: the person's own AI translates the installer into it | `ls installer/i18n/` |
| cli | `dfir` command + self-check units | `sudo dfir status` |
| notify | the bot sends the owner a Telegram message | message arrives = whole chain works |

At the end the installer prints the logins (generated passwords are shown once) and saves them to
**`~/DFIR_VAO_credentials.txt`** (only the person who ran sudo can read it; also `state/credentials.txt`), and waits until the person confirms they saved them; plus the **seal line** `dfir-seal-1:...` for the collector builder.

## 3. After install: checks you can ask the person to run

```bash
sudo dfir status                         # containers, AI, webhook, disk
docker ps --format '{{.Names}}\t{{.Status}}'
curl -s http://172.17.0.1:1234/v1/models | head -c 400
systemctl is-active dfir-sandbox-api owui-retention.timer
sudo cat /srv/dfir/state/install.log | tail -50
sudo dfir help-ai                        # status block without secrets, safe to paste to an AI
sudo dfir password                       # new password for the Open WebUI admin
```

Sandbox self-test (no case data needed):

```bash
printf 'ts,user\n2026-01-01T00:00:00Z,test\n' > /tmp/t.csv
sudo /srv/dfir/sandbox/analyze_file.sh /tmp/t.csv selftest && ls /srv/dfir/sandbox/jobs/selftest/out
sudo rm -rf /srv/dfir/sandbox/jobs/selftest
```

## 4. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Bot silent in Telegram | n8n workflow inactive after restart -> webhook 404; or ngrok domain wrong | `sudo dfir status`; `docker restart n8n`; re-run `sudo ./install.sh` (keeps answers) |
| "AI does not answer" | llama-swap/llm-router down, wrong server address, ufw blocks 172.17.0.1:1234 | `sudo dfir llm` to re-select; `sudo ufw allow from 172.16.0.0/12 to any port 1234` |
| GPU not used | NVIDIA driver / container toolkit missing | `nvidia-smi`; re-run installer (it installs the driver, then reboot) |
| Server in a VM, no GPU | consumer GPUs are not passed into VMs | choose `server`, run `DFIR_VAO_Host_LLM_Setup.ps1 (GitHub Releases)` on the Windows host |
| Open WebUI login unknown | generated password | `cat ~/DFIR_VAO_credentials.txt`, or set a new one: `sudo dfir password` |
| Attached file not analysed in chat | sandbox API down or token/URL valve wrong | `systemctl restart dfir-sandbox-api`; re-run installer step: `sudo ./install.sh` |
| Containers fail with `open sysctl net.ipv4.ip_unprivileged_port_start ... permission denied` | the server is an unprivileged LXC container (Proxmox CT, incus, LXD); Docker cannot set kernel options there | use a normal VM, or make the container privileged with nesting and AppArmor unconfined (Proxmox: `features: nesting=1`, privileged CT) |
| `pathlink_busy` error | `/srv/dfir` already exists | move it away, or clone directly into `/srv/dfir` |
| Collector archive "cannot decrypt" | built with another server's seal line | rebuild the collector with this server's `dfir-seal-1:...` line |
| Disk full | evidence + models | `df -h`; old cases in `cases/`; Docker: `docker system df` |

## 5. Changing things later

* AI / models: `sudo dfir llm` · bot language: `sudo dfir lang`
* Any installer section: `sudo ./install.sh` -> review screen -> pick the section. Everything again: `--reconfigure`.
* Non-interactive (servers, tests): `sudo ./install.sh --answers my_answers.env` (same keys as
  `state/install_answers.env`). `DRY_RUN=1` shows what would happen without changing the machine.
* Update: `cd /srv/dfir && git pull && sudo ./install.sh` (answers are kept, containers rebuilt).

## 6. Security model in one paragraph

Open WebUI: sign-up disabled, new users are `pending` until the admin approves them, code execution,
web search, direct connections and community sharing are off. Uploaded files are deleted after 24 h.
Files are parsed only inside the sandbox container (`--network none --user 65534 --cap-drop ALL
--read-only --security-opt no-new-privileges`, tmpfs work dir, CPU/RAM/PID/file-size limits, wall-clock
timeout, `--rm`). The sandbox API listens only on the Docker bridge and needs a token. Collector
archives are decrypted in `case-maintainer` with the server's private key, which never enters the sandbox.
Telegram messages go only to the owner chat chosen during install.
