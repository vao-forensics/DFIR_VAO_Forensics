# Update with trial run and rollback, against an installed test home whose agent is serving.
#   good.zip   = the current build repacked (new tag)           -> switched, model answers
#   noserver   = archive without llama-server.exe              -> refused at trial, current unchanged
#   stub.zip   = llama-server.exe that prints a version, cannot serve -> switched, model does not answer -> rolled back
param([string]$Exe, [string]$AgentHome)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$w = Join-Path $env:TEMP ('upd_' + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory $w | Out-Null
$cur = (Get-Content (Join-Path $AgentHome 'llama\current\TAG.txt')).Trim()
$g = Join-Path $w 'good'; Copy-Item -Recurse (Join-Path $AgentHome "llama\$cur") $g; Remove-Item (Join-Path $g 'TAG.txt')
'repacked for the update test' | Set-Content (Join-Path $g 'UPDATE_TEST.txt')
[IO.Compression.ZipFile]::CreateFromDirectory($g, "$w\good.zip")
$n = Join-Path $w 'noserver'; New-Item -ItemType Directory $n | Out-Null; 'x' | Set-Content (Join-Path $n 'readme.txt')
[IO.Compression.ZipFile]::CreateFromDirectory($n, "$w\noserver.zip")
$s = Join-Path $w 'stub'; New-Item -ItemType Directory $s | Out-Null
'class P { static int Main(string[] a) { System.Console.WriteLine("version: 9999 (stub, cannot serve)"); return 0; } }' | Set-Content "$w\stub.cs"
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo "/out:$s\llama-server.exe" "$w\stub.cs" | Out-Null
[IO.Compression.ZipFile]::CreateFromDirectory($s, "$w\stub.zip")

$fail = 0
function Step($name, $zip, [int]$wantRc, [string]$wantTag) {
    $t = Get-Date
    $out = & $Exe --update --from-zip $zip --home $AgentHome --lang en 2>&1 | Out-String
    $rc = $LASTEXITCODE
    $tag = (Get-Content (Join-Path $AgentHome 'llama\current\TAG.txt')).Trim()
    $okTag = if ($wantTag -eq 'new') { $tag -ne $cur -and $tag -like 'local-*' } else { $tag -eq $wantTag }
    $ok = ($rc -eq $wantRc) -and $okTag
    if (-not $ok) { $script:fail++ }
    "{0} {1}: rc={2} current={3} ({4:N0} s)`n     {5}" -f ($(if ($ok) { 'PASS' } else { 'FAIL' })), $name, $rc, $tag, ((Get-Date) - $t).TotalSeconds, ($out.Trim() -replace "`r?`n", ' | ')
}
Step 'archive without llama-server.exe is refused' "$w\noserver.zip" 1 $cur
Step 'build that cannot serve is rolled back' "$w\stub.zip" 1 $cur
Step 'good build is switched to and answers' "$w\good.zip" 0 'new'
$after = (Get-Content (Join-Path $AgentHome 'llama\current\TAG.txt')).Trim()
$builds = @(Get-ChildItem (Join-Path $AgentHome 'llama') -Directory | Where-Object Name -ne 'current').Name
"builds kept: $($builds -join ', ')"
if ($builds -notcontains $cur) { $fail++; "FAIL previous build $cur not kept for rollback" }
Remove-Item -Recurse -Force $w
if ($fail) { "$fail failed"; exit 1 } else { 'all passed' }
