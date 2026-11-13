# End-to-end test of DFIR VAO VM Wizard on a Windows PC (test only: .ps1 may be blocked by GPO elsewhere).
#   powershell -ExecutionPolicy Bypass -File test_vm_wizard.ps1 -Exe out\DFIR_VAO_VM_Wizard.exe -Hv wsl|vmware `
#       -Repo repo.tar.gz -AgentHome <test agent home> -Verify installer\guest\verify_install.sh [-SshKey id] [-Remove]
# Telegram: a local stub inside the guest (--test-tg-stub) and a fake token, never a real bot's token.
# Checks: guard refuses foreign names/folders; create; guest status reaches ok; verify_install.sh all PASS; remove.
param([string]$Exe, [string]$Hv, [string]$Repo, [string]$AgentHome, [string]$Verify, [string]$Name = "dfir-t7-$Hv",
      [string]$Dir = "$env:TEMP\dfir_t7_$Hv", [string]$SshKey = "$env:USERPROFILE\.ssh\id_ed25519", [int]$WaitMin = 150, [switch]$Remove)
$ErrorActionPreference = 'Continue'; $env:WSL_UTF8 = 1   # native stderr must not stop the test (PS 5.1)
$pass = 0; $fail = 0
function Check($n, $c) { if ($c) { "PASS $n"; $script:pass++ } else { "FAIL $n"; $script:fail++ } }

& $Exe --remove --hv wsl --name Ubuntu --dir $env:USERPROFILE 2>&1 | Out-Null
Check 'remove refuses a folder without the wizard marker' ($LASTEXITCODE -ne 0)
# the wizard is a window EXE (winexe): PowerShell only waits for it and keeps its output through a pipe
$det = (& $Exe --detect | Out-String) -split "`r?`n"
Check "detect lists $Hv as ready" ([bool]($det | Where-Object { $_ -match "^$Hv\tok" }))

$ca = @('--create', '--hv', $Hv, '--name', $Name, '--dir', $Dir, '--repo', $Repo, '--agent-home', $AgentHome, '--test-tg-stub',
  '--set', 'INSTALL_LANG=en', '--set', 'BOT_LANG=en', '--set', 'ACCEPT_TERMS=yes', '--set', 'DFIR_TG_BOT_TOKEN=100000001:STUB_not_a_real_bot_token_xxxxxxxxxx',
  '--set', 'OWNER_CHAT_ID=100000001', '--set', 'TUNNEL=url', '--set', 'NGROK_URL=https://itest.invalid')
if ($Hv -ne 'wsl') { $ca += @('--ram', '16', '--cpus', '4', '--disk', '150', '--ssh-key', "$SshKey.pub") }
& $Exe @ca | Out-Host
Check 'create' ($LASTEXITCODE -eq 0)

if ($LASTEXITCODE -ne 0) { "vm wizard e2e ($Hv): $pass passed, $fail failed (create failed, nothing to wait for)"; exit 1 }
$deadline = (Get-Date).AddMinutes($WaitMin)
do { $st = (& $Exe --status --hv $Hv --name $Name --dir $Dir | Out-String).Trim(); if ($st -eq 'ok' -or $st -like 'failed*') { break }; Start-Sleep 60 } while ((Get-Date) -lt $deadline)
Check "guest status ok ($st)" ($st -eq 'ok')

if ($Hv -eq 'wsl') {
  $v = '/mnt/' + $Verify.Substring(0, 1).ToLower() + ($Verify.Substring(2) -replace '\\', '/')
  $out = wsl.exe -d $Name -u root --exec /bin/bash $v /opt/dfir-vao
} else {
  $ip = (Select-String -Path "$Dir\serial.log" -Pattern 'ci-info: \|\s+(e\w+)\s+\|\s+True\s+\|\s+(\d+\.\d+\.\d+\.\d+)' | Select-Object -First 1).Matches[0].Groups[2].Value
  scp -i $SshKey -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL $Verify "dfir@${ip}:/tmp/verify_install.sh"
  $out = ssh -i $SshKey -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL "dfir@$ip" 'sudo bash /tmp/verify_install.sh /opt/dfir-vao'
}
$out
Check 'guest verify_install.sh all PASS' (($out | Out-String) -match 'verify: \d+ passed, 0 failed')
if ($Remove) { & $Exe --remove --hv $Hv --name $Name --dir $Dir | Out-Host; Check 'remove' ($LASTEXITCODE -eq 0) }
"vm wizard e2e ($Hv): $pass passed, $fail failed"
if ($fail) { exit 1 }
