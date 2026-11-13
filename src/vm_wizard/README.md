# DFIR VAO VM Wizard (Windows)

One EXE that makes the Linux machine for the DFIR bot on a Windows PC and installs the bot in it
with no questions inside Linux.

* **Where**: WSL2 (the GPU comes straight from the Windows NVIDIA driver), VMware Workstation,
  Hyper-V or VirtualBox. `--detect` shows what is ready on this PC.
* **Ubuntu 24.04** from `cloud-images.ubuntu.com` (WSL rootfs, cloud VMDK, Azure VHD for Hyper-V),
  SHA-256 checked against the `SHA256SUMS` of the same folder; every download goes to
  `provenance.jsonl` in the image cache (`%ProgramData%\DFIR_VAO_Wizard\images`).
* **Answers from the Host Agent**: `agent.json` of DFIR VAO Host Agent gives the port and the token;
  the address is the one the guest sees (VMware: VMnet8 adapter; VirtualBox NAT: 10.0.2.2; Hyper-V:
  Default Switch; WSL2: `__GATEWAY__`, replaced in the guest by its default gateway at every start).
  The window asks only for the Telegram token, owner chat_id, public HTTPS address, admin e-mail and
  the licence consent; passwords are generated and shown once at the end.
* **Into the guest**: VMs get a NoCloud seed ISO (label CIDATA, made with Windows' own IMAPI2):
  `user-data` (user `dfir`, SSH key, disk grown, unit `dfir-wizard.service`), `meta-data`,
  `install_answers.env`, `wizard.env`, `bootstrap.sh` (= `installer/guest/dfir-guest-bootstrap.sh`,
  embedded in the EXE at build time) and optionally `repo.tar.gz`. WSL gets the same files copied in,
  systemd switched on, and the bootstrap runs in the foreground.
* **Progress**: `--status` reads `/var/lib/dfir-wizard/status` (WSL) or the `DFIR-WIZARD-STATUS:` lines
  the bootstrap writes to the serial port (`serial.log` next to the VM).
* **Remove**: `--remove` deletes only a VM whose folder carries `dfir-vao-wizard.owner` with the same
  hypervisor and name, so an existing distribution or VM is never touched.
* **WSL keeps running**: WSL stops an idle distribution; the wizard adds a hidden keeper at logon
  (HKCU Run `DFIR_VAO_WSL_<name>` → `--keepalive <name>`). The WSL memory limit is the global one
  (`%UserProfile%\.wslconfig`, default half of RAM); the wizard does not change it.

Build: `powershell -ExecutionPolicy Bypass -File src\vm_wizard\make_wizard.ps1 -Out out`
(.NET Framework csc, nothing to install).

CLI (no arguments = window; it is a window EXE, so in PowerShell add `| Out-String` or use
`Start-Process -Wait` to wait for it and see its output): `--detect`, `--create --hv H --name N --repo URL|FILE.tar.gz [--dir D]
[--ram GB] [--cpus N] [--disk GB] [--agent-home D] [--answers FILE] [--set KEY=VALUE]... [--ssh-key PUB]
[--guest-password P] [--cache D] [--no-start] [--plan] [--test-tg-stub]`, `--status`, `--remove`,
`--user-data`, `--seed-iso OUT FILE...`, `--keepalive N`.

## Tests
`test_vm_wizard.ps1 -Exe ... -Hv wsl|vmware -Repo repo.tar.gz -AgentHome <test agent> -Verify
installer\guest\verify_install.sh [-Remove]`: guard refuses a folder without the marker, create,
guest status `ok`, `installer/guest/verify_install.sh` (the checks of the test from scratch) all PASS
inside the guest, remove. Telegram is a local stub in the guest (`installer/guest/test_tg_stub.py`
via `DFIR_TG_API`) with a fake token: install tests never hold a real bot's token.

Hyper-V and VirtualBox: commands are generated (`--plan` prints them) but were not run on the
development PC (neither installed there).
