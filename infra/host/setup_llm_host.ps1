# DFIR Bot - local LLM server on a Windows host with NVIDIA GPUs (the bot itself runs in a Linux VM).
#
# The layout the original install uses: VMware/Hyper-V cannot pass consumer GPUs into a VM, so the
# models run on the Windows host and the bot in the VM talks to them over the virtual network.
#
#   powershell -ExecutionPolicy Bypass -File infra\host\setup_llm_host.ps1 [-Profile auto|small|medium|large]
#              [-ModelsDir C:\dfir-models] [-InstallDir C:\dfir-llm] [-AllowFrom 192.168.0.0/16] [-NoModels]
#
# What it does (run as administrator):
#   1. reads the GPUs from nvidia-smi and picks the profile the Linux installer would pick
#   2. downloads llama-swap and the llama.cpp CUDA build from their GitHub releases
#   3. downloads the GGUF models of the profile from Hugging Face (resumable, skipped if present)
#   4. writes config.yaml with EVERY model name the bot calls (same table as installer/gen_llm_stack.py)
#   5. registers the scheduled task DFIR-LlamaSwap (SYSTEM, at boot) and a firewall rule for port 1234
#      open ONLY to -AllowFrom (default: the subnets of the VMware/Hyper-V virtual adapters)
# Then on the Linux VM: sudo ./install.sh -> AI: "server" -> URL http://<address printed below>:1234/v1
# Download (Windows): https://github.com/vao-forensics/DFIR_VAO_Forensics/releases (DFIR_VAO_Host_LLM_Setup.ps1)
param(
    [ValidateSet('auto', 'small', 'medium', 'large')][string]$Profile = 'auto',
    [string]$ModelsDir = 'C:\dfir-models',
    [string]$InstallDir = 'C:\dfir-llm',
    [string[]]$AllowFrom = @(),
    [switch]$NoModels,
    # preview / test: write only config.yaml to -InstallDir, touch nothing else; -FakeGpus "16,16" stands in for nvidia-smi
    [switch]$ConfigOnly,
    [ValidateSet('en', 'uk')][string]$Lang = 'en',
    [string]$FakeGpus = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Say($m) { Write-Host "* $m" -ForegroundColor Green }
function Warn($m) { Write-Host "! $m" -ForegroundColor Yellow }
function T($uk, $en) { if ($Lang -eq 'uk') { $uk } else { $en } }
if ($Lang -eq 'uk') { try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { } }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and -not $ConfigOnly) { throw (T 'Запустіть PowerShell від імені адміністратора (потрібні задача в планувальнику і правило брандмауера).' 'Run PowerShell as administrator (a scheduled task and a firewall rule are needed).') }

# ---- 1. GPUs -> profile (thresholds of installer/detect_hw.sh) ---------------------------------
if ($FakeGpus) {
    $i = 0
    $gpus = $FakeGpus -split ',' | ForEach-Object { [pscustomobject]@{ Index = $i++; Name = 'fake'; GB = [int]$_ } }
} else {
    if (-not (Get-Command nvidia-smi -ErrorAction SilentlyContinue)) { throw (T 'nvidia-smi не знайдено: встановіть драйвер NVIDIA.' 'nvidia-smi not found: install the NVIDIA driver.') }
    $gpus = & nvidia-smi --query-gpu=index,name,memory.total --format=csv,noheader,nounits |
        ForEach-Object { $p = $_ -split ',\s*'; [pscustomobject]@{ Index = [int]$p[0]; Name = $p[1]; GB = [int][math]::Floor([int]$p[2] / 1024) } }
}
$n = @($gpus).Count
$minGb = ($gpus | Measure-Object GB -Minimum).Minimum
$totGb = ($gpus | Measure-Object GB -Sum).Sum
$gpus | ForEach-Object { Say ("GPU {0}: {1}, {2} GB" -f $_.Index, $_.Name, $_.GB) }
if ($Profile -eq 'auto') {
    if ($n -eq 0 -or $minGb -lt 12) { throw (T "Замало відеопам'яті (найменша карта $minGb ГБ): потрібно від 12 ГБ на карту." "Not enough video memory (smallest card $minGb GB): 12 GB per card needed.") }
    elseif ($totGb -ge 80) { $Profile = 'large' }
    elseif ($totGb -ge 40 -and $n -ge 2) { $Profile = 'medium' }
    else { $Profile = 'small' }
}
if ($Profile -ne 'small' -and $n -lt 2) { throw (T "Профіль $Profile потребує 2+ карти, знайдено $n." "Profile $Profile needs 2+ cards, found $n.") }
Say (T "Профіль: $Profile ($n GPU, разом $totGb ГБ)" "Profile: $Profile ($n GPU, $totGb GB in total)")

New-Item -ItemType Directory -Force $InstallDir | Out-Null
if (-not $ConfigOnly) {
# ---- 2. llama-swap + llama.cpp -----------------------------------------------------------------
New-Item -ItemType Directory -Force $ModelsDir, "$InstallDir\llama" | Out-Null
function GhAsset($repo, $rx, [switch]$AnyRelease) {
    $h = @{ 'User-Agent' = 'dfir-setup' }
    $rels = if ($AnyRelease) { Invoke-RestMethod "https://api.github.com/repos/$repo/releases?per_page=5" -Headers $h }
            else { @(Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers $h) }
    foreach ($r in $rels) { foreach ($a in $r.assets) { if ($a.name -match $rx) { return $a.browser_download_url } } }
    throw (T "у релізах $repo немає файлу $rx" "no file $rx in the releases of $repo")
}
function Fetch($url, $dst) {
    if ((Test-Path $dst) -and (Get-Item $dst).Length -gt 0) { Say ((T "вже є: " "already here: ") + (Split-Path $dst -Leaf)); return }
    Say ((T "завантажую " "downloading ") + (Split-Path $dst -Leaf))
    & curl.exe -fL --retry 3 -C - -o "$dst.part" $url
    if ($LASTEXITCODE -ne 0) { throw ((T "не вдалося: " "download failed: ") + $url) }
    Move-Item -Force "$dst.part" $dst
}
$dl = Join-Path $InstallDir 'dl'
New-Item -ItemType Directory -Force $dl | Out-Null
$u = GhAsset 'mostlygeek/llama-swap' 'windows_amd64\.zip$'
Fetch $u (Join-Path $dl (Split-Path $u -Leaf))
Expand-Archive -Force (Join-Path $dl (Split-Path $u -Leaf)) $InstallDir
foreach ($rx in @('^llama-b\d+-bin-win-cuda-12\.4-x64\.zip$', '^cudart-llama-bin-win-cuda-12\.4-x64\.zip$')) {
    $u = GhAsset 'ggml-org/llama.cpp' $rx -AnyRelease
    Fetch $u (Join-Path $dl (Split-Path $u -Leaf))
    Expand-Archive -Force (Join-Path $dl (Split-Path $u -Leaf)) "$InstallDir\llama"
}
if (-not (Test-Path "$InstallDir\llama\llama-server.exe")) { throw (T 'у збірці llama.cpp немає llama-server.exe' 'the llama.cpp build has no llama-server.exe') }

}

# ---- 3. models ----------------------------------------------------------------------------------
$F20 = 'gpt-oss-20b-MXFP4.gguf'; $G31 = 'gemma-4-31B-it-Q4_K_S.gguf'; $B120 = 'gpt-oss-120b-MXFP4.gguf'
$src = @{
    $F20  = 'https://huggingface.co/ggml-org/gpt-oss-20b-GGUF/resolve/main/gpt-oss-20b-MXFP4.gguf'
    $G31  = 'https://huggingface.co/unsloth/gemma-4-31B-it-GGUF/resolve/main/gemma-4-31B-it-Q4_K_S.gguf'
    $B120 = 'https://huggingface.co/ggml-org/gpt-oss-120b-GGUF/resolve/main/gpt-oss-120b-MXFP4.gguf'
}
$need = switch ($Profile) { 'small' { @($F20) } 'medium' { @($F20, $G31) } 'large' { @($F20, $G31, $B120) } }
if (-not $NoModels -and -not $ConfigOnly) { foreach ($m in $need) { Fetch $src[$m] (Join-Path $ModelsDir $m) } }

# ---- 4. config.yaml (keep in step with installer/gen_llm_stack.py) -------------------------------
$CHAT = @('fast', 'gpt-oss-20b-heretic', 'translate-9b', 'gemma-2-9b-translate', 'agent-cli')
$REA = @('reasoner-31b-b', 'agent-30b')
$BIG = @('big', 'gpt-oss-120b', 'agent-big', 'smart', 'forensic-xl')
$server = "$InstallDir\llama\llama-server.exe"
function Model($name, $gguf, [int[]]$cards, [string[]]$aliases, $ttl = 86400) {
    $split = if ($cards.Count -eq 1) { '--split-mode none --main-gpu 0' } else { '--split-mode layer --tensor-split ' + (($cards | ForEach-Object { '1' }) -join ',') }
    $l = @("  `"$name`":", '    cmd: |',
        "      `"$server`"", "      -m `"$ModelsDir\$gguf`"", '      --host 127.0.0.1 --port ${PORT}',
        "      -ngl 99 $split", '      -fa auto --jinja', '      -c 65536 --cache-type-k q8_0 --cache-type-v q8_0', '      --no-webui',
        '    proxy: "http://127.0.0.1:${PORT}"', '    env:', ('      - "CUDA_VISIBLE_DEVICES=' + ($cards -join ',') + '"'), '    aliases:')
    $l += $aliases | ForEach-Object { "      - `"$_`"" }
    $l += "    ttl: $ttl", ''
    return $l
}
$head = @("# GENERATED by infra/host/setup_llm_host.ps1 for profile $Profile ($n GPU, smallest $minGb GB).",
    'healthCheckTimeout: 900', 'startPort: 5840', 'logLevel: info', '', 'models:')
$all = 0..($n - 1)
if ($Profile -eq 'small') {
    $body = Model 'gpt-small-20b' $F20 @(0) ($CHAT + @('reasoner-31b') + $REA + @('big-120b') + $BIG)
    $tail = @()
} else {
    $rest = 1..($n - 1)
    $rg = if ($minGb -ge 26) { @($rest[0]) } elseif ($rest.Count -ge 2) { @($rest[0], $rest[1]) } else { @($rest) }
    $bigAlias = if ($Profile -eq 'large') { @() } else { @('big-120b') + $BIG }
    if ($rg.Count * $minGb -lt 26) {
        $body = Model 'reasoner-31b' $G31 $all (@('gpt-small-20b') + $CHAT + $REA + $bigAlias)
        $tail = @()
    } else {
        $body = (Model 'gpt-small-20b' $F20 @(0) $CHAT) + (Model 'reasoner-31b' $G31 $rg ($REA + $bigAlias))
        $tail = @('matrix:', '  vars:', '    chat: "gpt-small-20b"', '    rea: "reasoner-31b"')
        if ($Profile -eq 'large') {
            $body += Model 'big-120b' $B120 $all $BIG 900
            $tail += @('    big: "big-120b"', '  sets:', '    main: "chat & rea"', '    bigset: "big"')
        } else { $tail += @('  sets:', '    main: "chat & rea"') }
    }
}
$cfg = Join-Path $InstallDir 'config.yaml'
[IO.File]::WriteAllText($cfg, (($head + $body + $tail) -join "`n") + "`n", (New-Object Text.UTF8Encoding($false)))
Say "config.yaml: $cfg"
if ($ConfigOnly) { return }

# ---- 5. autostart + firewall ---------------------------------------------------------------------
$start = Join-Path $InstallDir 'start.cmd'
$lines = @('@echo off', 'rem GENERATED by setup_llm_host.ps1')
if ($Profile -eq 'large') {
    # big-120b splits layers over every card; without a clock floor each card idles between its turns
    # (measured 6-7 tok/s instead of 65 on 6x RTX 4080 SUPER). Limits come from each card's own table.
    foreach ($g in $gpus) {
        $top = & nvidia-smi -i $g.Index --query-supported-clocks=memory,graphics --format=csv,noheader,nounits |
            ForEach-Object { $p = $_ -split ',\s*'; [pscustomobject]@{ Mem = [int]$p[0]; Gr = [int]$p[1] } } |
            Sort-Object Mem, Gr -Descending | Select-Object -First 1
        if ($top) {
            $lo = [math]::Min(1500, $top.Gr)
            $lines += "nvidia-smi -i $($g.Index) -lgc $lo,$($top.Gr) >nul 2>&1"
            $lines += "nvidia-smi -i $($g.Index) -lmc $($top.Mem),$($top.Mem) >nul 2>&1"
        }
    }
}
$lines += "`"$InstallDir\llama-swap.exe`" -config `"$cfg`" -listen 0.0.0.0:1234 -watch-config"
[IO.File]::WriteAllText($start, ($lines -join "`r`n") + "`r`n")
$act = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$start`""
$trg = New-ScheduledTaskTrigger -AtStartup
$set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'DFIR-LlamaSwap' -Action $act -Trigger $trg -Settings $set -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'DFIR-LlamaSwap'

if ($AllowFrom.Count -eq 0) {
    # subnets of the virtual adapters the VM sits behind (VMware VMnet*, Hyper-V vEthernet)
    $AllowFrom = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'VMnet|vEthernet' } |
        ForEach-Object { $o = ([ipaddress]$_.IPAddress).GetAddressBytes(); "{0}.{1}.{2}.0/24" -f $o[0], $o[1], $o[2] } | Sort-Object -Unique
}
if (-not $AllowFrom) { Warn (T 'Віртуальних адаптерів не знайдено: порт 1234 НЕ відкрито. Перезапустіть з -AllowFrom <підмережа ВМ>.' 'No virtual adapters found: port 1234 is NOT opened. Run again with -AllowFrom <VM subnet>.') }
else {
    Get-NetFirewallRule -DisplayName 'DFIR LLM 1234' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName 'DFIR LLM 1234' -Direction Inbound -Protocol TCP -LocalPort 1234 -RemoteAddress $AllowFrom -Action Allow | Out-Null
    Say ((T 'Порт 1234 відкрито лише для: ' 'Port 1234 is open only for: ') + ($AllowFrom -join ', '))
}

Start-Sleep 5
try { $null = Invoke-RestMethod 'http://127.0.0.1:1234/v1/models' -TimeoutSec 15; Say (T 'llama-swap відповідає на :1234' 'llama-swap answers on :1234') }
catch { Warn ((T "llama-swap ще не відповідає: дивіться " "llama-swap does not answer yet: see ") + "$InstallDir (task DFIR-LlamaSwap)") }
$addr = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'VMnet|vEthernet' } | Select-Object -ExpandProperty IPAddress
Say (T 'Далі у Linux-ВМ: sudo ./install.sh -> ШІ: "server" (свій сервер) -> адреса:' 'Next, in the Linux VM: sudo ./install.sh -> AI: "server" (own server) -> address:')
$addr | ForEach-Object { Write-Host "      http://${_}:1234/v1" }
