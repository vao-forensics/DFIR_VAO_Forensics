# config.yaml from the agent == config.yaml from infra/host/setup_llm_host.ps1 for the same cards
param([string]$Exe, [string]$Ps1)
$ErrorActionPreference = 'Stop'
$fail = 0
foreach ($set in @('16', '16,16', '24,24', '16,16,16', '12,12,12', '16,16,16,16,16', '16,16,16,16,16,16', '24,24,24,24')) {
    $w = Join-Path $env:TEMP ('parity_' + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory $w | Out-Null
    & powershell -NoProfile -ExecutionPolicy Bypass -File $Ps1 -ConfigOnly -FakeGpus $set -InstallDir "$w\ps" -ModelsDir 'M:\models' | Out-Null
    $home2 = Join-Path $w 'agent'; New-Item -ItemType Directory $home2 | Out-Null
    @{ ModelsDir = 'M:\models' } | ConvertTo-Json | Set-Content (Join-Path $home2 'agent.json')
    & $Exe --gen-config "$w\agent.yaml" --fake-gpus $set --home $home2 | Out-Null
    $a = (Get-Content "$w\ps\config.yaml") -replace [regex]::Escape("$w\ps\llama\llama-server.exe"), 'SERVER' | Select-Object -Skip 1
    $b = (Get-Content "$w\agent.yaml") -replace [regex]::Escape("$home2\llama\current\llama-server.exe"), 'SERVER' | Select-Object -Skip 1
    $d = Compare-Object $a $b -SyncWindow 0
    $prof = ((Get-Content "$w\agent.yaml" -TotalCount 1) -split 'profile ')[1]
    if ($d) { $fail++; "FAIL $set :"; $d | Out-String } else { "ok   $set -> $prof, $($a.Count) lines identical" }
    Remove-Item -Recurse -Force $w
}
if ($fail) { exit 1 }
