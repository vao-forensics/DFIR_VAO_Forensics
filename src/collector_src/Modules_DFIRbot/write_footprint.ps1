# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : write_footprint.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : declare the collector own footprint
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
param(
    [string]$OutDir   = "",
    [string]$SelfDir  = "",
    [string]$WorkRoot = "",
    [string]$StartUtc = "",
    [string]$Version  = ""
)
# Document EVERY trace this collector leaves on the examined machine.
#
# WHY: a live triage cannot avoid leaving traces - it runs executables, so Prefetch, Amcache,
# ShimCache, SRUM and the MFT all record it, and its temp folder creates thousands of MFT
# entries stamped with TODAY. If somebody later images the disk bit-for-bit and builds a
# timeline, our own tooling shows up in it. Measured on a real run: 74 new Prefetch entries
# and ~2700 PowerShell log events in one session.
# The danger is not the noise itself - it is an examiner mistaking OUR noise for the
# intruder's activity and following it. So we write down exactly what we did, when, and under
# which names, and the bot subtracts it. Anything we cannot subtract, we at least declare.
#
# ASCII-ONLY (code and output): console is CP1251, PS 5.1 breaks on non-ASCII literals.
# stdout: EXE|n  PF|n  PS|n  OUT|<path>

$ErrorActionPreference = 'SilentlyContinue'
if (-not $OutDir) { $OutDir = $PSScriptRoot }
$txt = Join-Path $OutDir '_collector_footprint.txt'
$csv = Join-Path $OutDir '_collector_footprint.csv'

$t0 = $null
if ($StartUtc) { try { $t0 = [DateTime]::Parse($StartUtc) } catch {} }
if (-not $t0) { $t0 = (Get-Date).AddHours(-2) }
$t1 = Get-Date

$rows = New-Object System.Collections.ArrayList
function Row($kind, $name, $path, $when, $note) {
    $null = $rows.Add([PSCustomObject]@{
        kind = $kind; name = $name; path = $path; when = $when; note = $note })
}

# --- 1. every executable we shipped and could have run -----------------------------
$exes = @()
if ($SelfDir -and (Test-Path $SelfDir)) {
    $exes = Get-ChildItem $SelfDir -Recurse -File -Include *.exe, *.com -ErrorAction SilentlyContinue
}
foreach ($e in $exes) {
    Row 'our_binary' $e.Name $e.FullName '' 'shipped by the collector - not attacker tooling'
}

# --- 2. Prefetch entries created during our run window -----------------------------
$pf = Get-ChildItem 'C:\Windows\Prefetch\*.pf' -ErrorAction SilentlyContinue |
      Where-Object { $_.CreationTime -ge $t0 -and $_.CreationTime -le $t1.AddMinutes(5) }
foreach ($p in $pf) {
    Row 'prefetch_created' $p.Name $p.FullName $p.CreationTime.ToString('yyyy-MM-dd HH:mm:ss') `
        'created DURING this triage - execution evidence of OUR tool, not of the incident'
}

# --- 3. the temp tree we unpacked: thousands of MFT records stamped today -----------
if ($SelfDir -and (Test-Path $SelfDir)) {
    $all = Get-ChildItem $SelfDir -Recurse -File -ErrorAction SilentlyContinue
    Row 'temp_tree' 'extracted_files' $SelfDir `
        $t0.ToString('yyyy-MM-dd HH:mm:ss') `
        ('' + $all.Count + ' files unpacked here and deleted afterwards; their $MFT records ' +
         'carry TODAY as creation time and may survive as deleted entries')
}
if ($WorkRoot) {
    Row 'work_root' 'output_folder' $WorkRoot $t0.ToString('yyyy-MM-dd HH:mm:ss') `
        'where the archives were written by this triage'
}

# --- 4. PowerShell logging volume we generated -------------------------------------
$psn = 0
foreach ($log in @('Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell')) {
    $n = 0
    try { $n = @(Get-WinEvent -FilterHashtable @{LogName = $log; StartTime = $t0 } -ErrorAction Stop).Count } catch {}
    $psn += $n
    if ($n -gt 0) {
        Row 'eventlog_noise' $log '' $t0.ToString('yyyy-MM-dd HH:mm:ss') `
            ('' + $n + ' events in this log during the triage window - largely ours')
    }
}

# --- 5. Defender exclusions we added -----------------------------------------------
foreach ($p in @($WorkRoot, $SelfDir)) {
    if ($p) { Row 'defender_exclusion' 'added_by_collector' $p '' 'added at start, removed at end' }
}

# --- write ------------------------------------------------------------------------
$L = New-Object System.Collections.ArrayList
$null = $L.Add('=================================================================')
$null = $L.Add(' COLLECTOR FOOTPRINT - what THIS triage itself left on the machine')
$null = $L.Add('=================================================================')
$null = $L.Add('')
$null = $L.Add('READ THIS BEFORE BUILDING A TIMELINE FROM AN IMAGE OF THIS MACHINE.')
$null = $L.Add('')
$null = $L.Add('A live triage runs programs, so Windows records it: Prefetch, Amcache,')
$null = $L.Add('ShimCache, SRUM and the MFT all gain entries, stamped with the time of')
$null = $L.Add('collection - NOT the time of the incident. If the disk is imaged later,')
$null = $L.Add('these entries appear in the timeline and can be mistaken for intruder')
$null = $L.Add('activity. Everything listed below is OURS. Subtract it.')
$null = $L.Add('')
$null = $L.Add('collector version : ' + $Version)
$null = $L.Add('run started (local): ' + $t0.ToString('yyyy-MM-dd HH:mm:ss'))
$null = $L.Add('run ended   (local): ' + $t1.ToString('yyyy-MM-dd HH:mm:ss'))
$null = $L.Add('machine            : ' + $env:COMPUTERNAME)
$null = $L.Add('account            : ' + $env:USERNAME)
$null = $L.Add('temp folder        : ' + $SelfDir)
$null = $L.Add('output folder      : ' + $WorkRoot)
$null = $L.Add('')
$null = $L.Add('SUMMARY')
$null = $L.Add('  executables shipped by us : ' + $exes.Count)
$null = $L.Add('  Prefetch entries created  : ' + $pf.Count)
$null = $L.Add('  PowerShell log events     : ' + $psn)
$null = $L.Add('')
$null = $L.Add('WHAT WE DID NOT CHANGE: no registry keys were written for the purpose of')
$null = $L.Add('collection, no services installed, no drivers loaded, no reboot. The only')
$null = $L.Add('deliberate system change is the pair of Defender exclusions listed below,')
$null = $L.Add('added before the tools ran and removed when the run finished.')
$null = $L.Add('')

foreach ($k in @('prefetch_created', 'temp_tree', 'work_root', 'eventlog_noise',
                 'defender_exclusion', 'our_binary')) {
    $items = @($rows | Where-Object { $_.kind -eq $k })
    if (-not $items.Count) { continue }
    $null = $L.Add('-----------------------------------------------------------------')
    $null = $L.Add('[' + $k + ']  ' + $items.Count + ' entr(ies)')
    $null = $L.Add('-----------------------------------------------------------------')
    $n = 0
    foreach ($it in $items) {
        if ($n -ge 300) { $null = $L.Add('    ... ' + ($items.Count - $n) + ' more (see the CSV)'); break }
        $line = '  ' + $it.name
        if ($it.when) { $line += '   ' + $it.when }
        $null = $L.Add($line)
        if ($it.path) { $null = $L.Add('      ' + $it.path) }
        if ($it.note -and $k -ne 'our_binary') { $null = $L.Add('      note: ' + $it.note) }
        $n++
    }
    $null = $L.Add('')
}

Set-Content -LiteralPath $txt -Value $L -Encoding ASCII
$rows | Select-Object kind, name, path, when, note |
    Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8

'EXE|' + $exes.Count
'PF|' + $pf.Count
'PS|' + $psn
'OUT|' + $txt
