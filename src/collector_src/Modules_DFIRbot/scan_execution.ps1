# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : scan_execution.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : ShimCache/Amcache/Prefetch execution analysis (READ-ONLY)
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
param(
    [string]$CsvDir  = "",
    [string]$OutFile = "",
    [string]$OutCsv  = "",
    [int]$MaxPerRule = 200
)
# Our own execution-artifact analyser over the CSVs the KAPE modules already produce
# (AppCompatCacheParser = ShimCache, AmcacheParser, PECmd = Prefetch).
#
# WHY OURS AND NOT AppCompatProcessor.py: that tool is Python 2, refuses to run on Windows,
# and builds a second database with its own schema. The VALUE is in its methods, not its code.
# Ported here: misplaced system binaries, execution from staging folders, admin-share (c$)
# lateral movement, look-alike names (Levenshtein), rename pattern, timestamp copying,
# recon bursts. Its own signature file had SIX dead rules (a literal "{}" is not a
# quantifier in a regex) - so every rule below is written from scratch and unit-checked.
#
# TIMESTAMP SEMANTICS - the single most abused thing in this artefact family:
#   ShimCache LastModifiedTimeUTC = the FILE's mtime. NOT an execution time. On Win7+
#     ShimCache stores no execution time at all, and a row does not even prove execution.
#   Amcache  FileKeyLastWriteTimestamp = when the entry was written (~first seen).
#   Prefetch LastRun = a REAL execution time; RunCount is real too.
# Every finding therefore carries when_kind so nothing downstream can mislabel it.
#
# ASCII-ONLY (code and output): console is CP1251, PS 5.1 breaks on non-ASCII literals.
# stdout: TOTAL|n  RULE|<id>=<count> (repeated)  HOSTS|<c$ hosts>  OUT|<path>

if (-not $CsvDir)  { $CsvDir  = $PSScriptRoot }
if (-not $OutFile) { $OutFile = Join-Path $CsvDir 'execution_findings.txt' }
if (-not $OutCsv)  { $OutCsv  = Join-Path $CsvDir 'execution_findings.csv' }

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------- helpers ----
function Get-Csvs([string]$pattern) {
    Get-ChildItem $CsvDir -Recurse -File -Filter '*.csv' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $pattern }
}

function Norm([string]$p) {
    if (-not $p) { return '' }
    ($p -replace '/', '\').ToLower()
}

# Match a whole path SEGMENT, never a substring: '\temp' as a substring also matches
# '\templates'. This exact mistake produced 22,668 false hits once already.
function Has-Segment([string]$lowpath, [string[]]$segs) {
    $parts = $lowpath.Split('\')
    foreach ($s in $segs) { if ($parts -contains $s) { return $true } }
    return $false
}

# Damerau-Levenshtein (optimal string alignment), i.e. plain Levenshtein PLUS the swap of two
# adjacent characters counted as ONE edit.
# WHY IT MUST COUNT SWAPS: the textbook typosquat of svchost.exe is scvhost.exe, and that is a
# transposition - plain Levenshtein scores it 2, so a distance-1 rule misses the single most
# famous example in the whole class. Caught by the recall test, not by reading the code.
function Lev([string]$a, [string]$b) {
    $n = $a.Length; $m = $b.Length
    if ($n -eq 0) { return $m }
    if ($m -eq 0) { return $n }
    if ([Math]::Abs($n - $m) -gt 2) { return 9 }
    $d = New-Object 'int[,]' ($n + 1), ($m + 1)
    for ($i = 0; $i -le $n; $i++) { $d[$i, 0] = $i }
    for ($j = 0; $j -le $m; $j++) { $d[0, $j] = $j }
    for ($i = 1; $i -le $n; $i++) {
        for ($j = 1; $j -le $m; $j++) {
            $cost = 1
            if ($a[$i - 1] -eq $b[$j - 1]) { $cost = 0 }
            $min = $d[($i - 1), $j] + 1
            $e = $d[$i, ($j - 1)] + 1
            if ($e -lt $min) { $min = $e }
            $f = $d[($i - 1), ($j - 1)] + $cost
            if ($f -lt $min) { $min = $f }
            if ($i -gt 1 -and $j -gt 1 -and
                $a[$i - 1] -eq $b[$j - 2] -and $a[$i - 2] -eq $b[$j - 1]) {
                $t = $d[($i - 2), ($j - 2)] + 1
                if ($t -lt $min) { $min = $t }
            }
            $d[$i, $j] = $min
        }
    }
    return $d[$n, $m]
}

$FINDINGS = New-Object System.Collections.ArrayList
function Add-Finding($rule, $sev, $name, $path, $when, $kind, $art, $detail, $sha1) {
    $null = $FINDINGS.Add([PSCustomObject]@{
        rule = $rule; severity = $sev; name = $name; path = $path
        when = $when; when_kind = $kind; artifact = $art; detail = $detail; sha1 = $sha1
    })
}

# ---------------------------------------------------------------- rule data ----
# EVERY threshold below was set by running this script against a KNOWN-CLEAN machine and
# driving the false positives to (near) zero, then re-checking recall against the malicious
# paths from the Course lab. The first draft produced 310 findings on that clean host; the
# causes are recorded next to each fix because they are all the same mistake in disguise:
# matching too loosely.

# Tier 1: these NEVER legitimately live outside System32/SysWOW64.
$CORE_SYSBIN = @('svchost.exe','lsass.exe','csrss.exe','smss.exe','wininit.exe','winlogon.exe',
                 'services.exe','spoolsv.exe','taskhostw.exe','conhost.exe','sihost.exe',
                 'ctfmon.exe','dwm.exe','searchindexer.exe','wuauclt.exe','lsaiso.exe',
                 'werfault.exe','fontdrvhost.exe','sppsvc.exe','dllhost.exe')
# Tier 2: real Windows tools that ALSO ship inside legitimate toolchains - Git for Windows,
# cygwin and msys all carry their own whoami.exe/find.exe/sort.exe. Flagging those was the
# single sysbin false positive on the clean host. So tier 2 counts only inside a staging dir.
$TOOL_SYSBIN = @('cmd.exe','powershell.exe','net.exe','net1.exe','nltest.exe','whoami.exe',
                 'schtasks.exe','wscript.exe','cscript.exe','mshta.exe','certutil.exe',
                 'bitsadmin.exe','wmic.exe','reg.exe','regsvr32.exe','rundll32.exe',
                 'msiexec.exe','explorer.exe','at.exe','psexec.exe')
$SYSDIRS = @('system32','syswow64','winsxs','sysnative')

# Vendor-signed territory. A binary here is not interesting merely for sitting in a folder
# whose NAME resembles a staging folder (this is what made "intel" match Program Files\Intel).
$TRUSTED_RE = '^[a-z]:\\(program files( \(x86\))?|windows\\(system32|syswow64|winsxs|servicing|softwaredistribution|microsoft\.net|assembly|windowsapps|immersivecontrolpanel|systemapps)|programdata\\package cache)\\'

# Installer scaffolding: WiX bootstrappers unpack into <GUID>\.ba|.be|.cr, and 7-Zip SFX
# installers into 7zS<hex>. Both live in Temp by design and are overwhelmingly legitimate.
$INSTALLER_RE = '\\7zs[0-9a-f]{4,}\\|\\\{[0-9a-f-]{36}\}\\\.(ba|be|cr)\\|\\is-[a-z0-9]{6}\.tmp\\|\\_is[0-9]+\\' +
                # Windows servicing unpacks these into a GUID folder in Temp on every update.
                '|\\temp\\[0-9a-f{}-]{32,38}\\(dismhost|mpsigstub|mprecovery|wimserv)\.exe$' +
                '|\\temp\\(mpsigstub|mprecovery|dismhost)\.exe$'

# Our own kit: KAPE lays its tools out as ...\Modules\bin\... - that is us, not the suspect.
$SELF_RE = '\\modules\\bin\\|\\dfir_triage\\|\\dfirtriage_|\\dfircollector_|\\kape\\' +
           '|\\kape\.exe$|\\(mftecmd|pecmd|amcacheparser|appcompatcacheparser|evtxecmd|recmd' +
           '|sbecmd|srumecmd|sqlecmd|jlecmd|lecmd|rbcmd|bstrings|hayabusa|chainsaw|thor-lite' +
           '|browserparser|hindsight|bitsparser|dhparser|mplog_parser|leveldbdumper)\.exe$'

# Staging folders, each ANCHORED so the name cannot match deep inside a vendor path.
# 'intel'/'web'/'recovery' are only meaningful at the ROOT of a drive.
$STAGING_RE = [ordered]@{
    'root_odd'   = '^[a-z]:\\(intel|web|recovery|perflogs|temp)\\'
    'recycle'    = '\\\$recycle\.bin\\|\\recycler\\'
    'sysvolinfo' = '\\system volume information\\'
    'public'     = '\\users\\public\\'
    'winsub'     = '^[a-z]:\\windows\\(debug|help|media|ime|addins|repair|security|fonts|tasks|tracing|update)\\'
    'profile'    = '\\users\\[^\\]+\\(downloads|documents|desktop|music|pictures|videos)\\'
    'appdata'    = '\\appdata\\(local|roaming)\\[^\\]+$'
    'temp'       = '\\temp\\'
    'sysprofile' = '\\config\\systemprofile\\'
}

# Tools that are individually legitimate; a CLUSTER of them in a short window is recon.
$RECON = @('systeminfo.exe','tasklist.exe','ipconfig.exe','netstat.exe','net.exe','net1.exe',
           'quser.exe','whoami.exe','where.exe','nltest.exe','arp.exe','route.exe',
           'nbtstat.exe','hostname.exe','query.exe','dsquery.exe','netsh.exe')

# Look-alike pairs that are both real Windows/vendor binaries - never flag these.
$LEVEN_OK = @{
    'ftp.exe'='tftp.exe'; 'sc.exe'='scw.exe'; 'tracert.exe'='tracerpt.exe';
    'dxdiag.exe'='dcdiag.exe'; 'taskhost.exe'='taskhostw.exe'; 'fsutil.exe'='dfsutil.exe';
    'net.exe'='net1.exe'; 'chkdsk.exe'='chkntfs.exe'; 'cmd.exe'='cmdl32.exe'
}

function Is-Self([string]$low)      { return ($low -match $SELF_RE) }
function Is-Trusted([string]$low)  { return ($low -match $TRUSTED_RE) }
function Is-Installer([string]$low){ return ($low -match $INSTALLER_RE) }
# Which staging bucket (if any) a path falls into; '' when none.
function Staging-Of([string]$low) {
    foreach ($k in $STAGING_RE.Keys) { if ($low -match $STAGING_RE[$k]) { return $k } }
    return ''
}
function Is-Exec([string]$low) { return ($low -match '\.(exe|scr|com|pif|bat|cmd|ps1|vbs|js|jse|wsf|dll|sys)$') }

# ---------------------------------------------------------------- load ----
$rows = New-Object System.Collections.ArrayList   # unified: path/name/when/kind/art/sha1
$shim = New-Object System.Collections.ArrayList   # ShimCache only (order + rename logic)

foreach ($f in (Get-Csvs 'AppCompatCache')) {
    foreach ($r in (Import-Csv $f.FullName)) {
        $p = $r.Path
        if (-not $p) { continue }
        $o = [PSCustomObject]@{
            path = $p; low = (Norm $p); name = ($p -split '\\')[-1]
            when = $r.LastModifiedTimeUTC; kind = 'file_mtime(shimcache)'
            art  = 'ShimCache'; sha1 = ''; pos = $r.CacheEntryPosition
        }
        $null = $rows.Add($o); $null = $shim.Add($o)
    }
}
foreach ($f in (Get-Csvs 'Amcache.*(Unassociated|Associated)FileEntries')) {
    foreach ($r in (Import-Csv $f.FullName)) {
        $p = $r.FullPath
        if (-not $p) { continue }
        $null = $rows.Add([PSCustomObject]@{
            path = $p; low = (Norm $p); name = $r.Name
            when = $r.FileKeyLastWriteTimestamp; kind = 'first_seen(amcache)'
            art  = 'Amcache'; sha1 = $r.SHA1; pos = ''
        })
    }
}
$pe = New-Object System.Collections.ArrayList
foreach ($f in (Get-Csvs 'PECmd_Output\.csv$')) {
    foreach ($r in (Import-Csv $f.FullName)) {
        if (-not $r.ExecutableName) { continue }
        $null = $pe.Add([PSCustomObject]@{
            name = $r.ExecutableName.ToLower(); last = $r.LastRun; runs = $r.RunCount
            created = $r.SourceCreated
        })
    }
}

# ---------------------------------------------------------------- rules ----

# R1 - a tier-1 system binary anywhere but System32/SysWOW64. The Course lab's
# C:\Windows\Update\svchost.exe and \Windows\Update\werfault.exe are exactly this.
foreach ($o in $rows) {
    $n = $o.name.ToLower()
    if ($CORE_SYSBIN -notcontains $n) { continue }
    if (Is-Self $o.low) { continue }
    if (Has-Segment $o.low $SYSDIRS) { continue }
    Add-Finding 'sysbin_wrong_place' 'HIGH' $o.name $o.path $o.when $o.kind $o.art `
        'tier-1 Windows system binary outside System32/SysWOW64' $o.sha1
}

# R1b - a tier-2 tool only counts inside a staging folder: Git/cygwin ship their own
# whoami.exe and flagging those was pure noise on the clean host.
foreach ($o in $rows) {
    $n = $o.name.ToLower()
    if ($TOOL_SYSBIN -notcontains $n) { continue }
    if ((Is-Self $o.low) -or (Has-Segment $o.low $SYSDIRS) -or (Is-Installer $o.low)) { continue }
    $st = Staging-Of $o.low
    if (-not $st) { continue }
    Add-Finding 'sysbin_in_staging' 'HIGH' $o.name $o.path $o.when $o.kind $o.art `
        ('Windows tool copied into a staging folder (' + $st + ')') $o.sha1
}

# R2 - any executable running from a staging folder.
foreach ($o in $rows) {
    # NOTE the parentheses around EVERY call: `if (Is-Self $x -or (Is-Trusted $x))` passes
    # '-or' and the next value as ARGUMENTS to Is-Self, so the rest of the condition is
    # silently dropped. Verified: the callee received 2 extra args. That bug had disabled
    # the trusted/installer filters entirely.
    if ((Is-Self $o.low) -or (Is-Trusted $o.low) -or (Is-Installer $o.low)) { continue }
    if (-not (Is-Exec $o.low)) { continue }
    $st = Staging-Of $o.low
    if (-not $st) { continue }
    # 'profile' (Downloads/Desktop/Documents) is where ordinary people keep installers, so it
    # is CONTEXT, not an alert - 64 hits on the clean host, every one legitimate. It still
    # matters (the lab found EdgeUpdater.exe in Downloads), so it is kept at LOW and listed
    # separately instead of being deleted.
    $sev = 'MEDIUM'
    if ($st -eq 'profile') { $sev = 'LOW' }
    elseif ($st -eq 'recycle' -or $st -eq 'sysvolinfo' -or $st -eq 'winsub' -or $st -eq 'sysprofile') { $sev = 'HIGH' }
    Add-Finding ('staging_' + $st) $sev $o.name $o.path $o.when $o.kind $o.art `
        ('executable in staging folder: ' + $st) $o.sha1
}

# R3 - run straight out of an ARCHIVER temp folder. Only Rar$: that is the "user opened the
# attachment in WinRAR and hit Run" pattern. 7zS<hex> was dropped - it is the ordinary 7-Zip
# self-extracting installer and produced only vendor installers on the clean host.
foreach ($o in $rows) {
    if ($o.low -match '\\rar\$[a-z0-9]+' -and (Is-Exec $o.low)) {
        Add-Finding 'archiver_temp' 'HIGH' $o.name $o.path $o.when $o.kind $o.art `
            'executed from WinRAR temp - opened directly from an archive/attachment' $o.sha1
    }
}

# R4 - admin-share / UNC. Yields NEW hosts to investigate, which is why it is so valuable.
# Must not match the local device form \\?\C: - that is the trap in the original rule set.
$hosts = @{}
foreach ($o in $rows) {
    if ($o.low -notmatch '^\\\\[^\\?]') { continue }
    $h = ($o.low -split '\\')[2]
    if (-not $h) { continue }
    $sev = 'MEDIUM'; $why = 'executable referenced over a network share'
    if ($o.low -match '^\\\\[^\\]+\\[a-z]\$\\' -or $o.low -match '^\\\\[^\\]+\\admin\$\\') {
        $sev = 'HIGH'; $why = 'ADMIN SHARE (c$/admin$) - classic lateral movement'
    }
    $hosts[$h] = $true
    Add-Finding 'unc_admin_share' $sev $o.name $o.path $o.when $o.kind $o.art $why $o.sha1
}

# R5 - look-alike name (Levenshtein 1) against a real system binary, e.g. scvhost.exe.
# TWO limits learned from the clean host, where this fired 15 times, all legitimate:
#   * short stems are worthless - csc.exe, mc.exe and gc.exe are all one edit from sc.exe.
#     Requiring a stem of 5+ characters kills that whole class.
#   * a look-alike sitting in vendor-signed territory is not a finding.
$ALL_SYSBIN = $CORE_SYSBIN + $TOOL_SYSBIN
$seen = @{}
foreach ($o in $rows) {
    $n = $o.name.ToLower()
    if (-not $n -or $n -notmatch '\.exe$') { continue }
    if ($ALL_SYSBIN -contains $n) { continue }
    # NOTE the parentheses around EVERY call: `if (Is-Self $x -or (Is-Trusted $x))` passes
    # '-or' and the next value as ARGUMENTS to Is-Self, so the rest of the condition is
    # silently dropped. Verified: the callee received 2 extra args. That bug had disabled
    # the trusted/installer filters entirely.
    if ((Is-Self $o.low) -or (Is-Trusted $o.low) -or (Is-Installer $o.low)) { continue }
    if (($n -replace '\.exe$', '').Length -lt 5) { continue }
    $key = $n + '|' + $o.low
    if ($seen.ContainsKey($key)) { continue }
    foreach ($s in $ALL_SYSBIN) {
        if (($s -replace '\.exe$', '').Length -lt 5) { continue }
        if ((Lev $n $s) -ne 1) { continue }
        if ($LEVEN_OK[$s] -eq $n -or $LEVEN_OK[$n] -eq $s) { continue }
        $seen[$key] = $true
        Add-Finding 'lookalike_name' 'HIGH' $o.name $o.path $o.when $o.kind $o.art `
            ('one character away from the real ' + $s) $o.sha1
        break
    }
}

# R6 - masquerading as a document: double extension.
foreach ($o in $rows) {
    if (Is-Self $o.low) { continue }
    if ($o.low -match '\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|txt|rtf|zip|rar)\.(exe|scr|com|pif|bat|cmd|js|vbs)$') {
        Add-Finding 'double_extension' 'HIGH' $o.name $o.path $o.when $o.kind $o.art `
            'double extension - pretends to be a document' $o.sha1
    }
}

# R7 - rename pattern: same folder + same file mtime + different names (ShimCache only).
# Everything installed by one installer shares an mtime, so on the clean host this fired 84
# times inside Program Files / SoftwareDistribution. Restricted to staging folders, where a
# shared mtime across different names really does suggest a rename.
$byKey = @{}
foreach ($o in $shim) {
    if (-not $o.when) { continue }
    # NOTE the parentheses around EVERY call: `if (Is-Self $x -or (Is-Trusted $x))` passes
    # '-or' and the next value as ARGUMENTS to Is-Self, so the rest of the condition is
    # silently dropped. Verified: the callee received 2 extra args. That bug had disabled
    # the trusted/installer filters entirely.
    if ((Is-Self $o.low) -or (Is-Trusted $o.low) -or (Is-Installer $o.low)) { continue }
    # Downloads and Temp legitimately hold whole families of co-installed binaries that share
    # one mtime (hashcat32/hashcat64, vc_redist x86/x64, driver packages), so only the folders
    # where nothing should be installed at all can raise this.
    $st = Staging-Of $o.low
    if ($st -ne 'recycle' -and $st -ne 'sysvolinfo' -and $st -ne 'winsub' -and
        $st -ne 'sysprofile' -and $st -ne 'public' -and $st -ne 'root_odd') { continue }
    $dir = $o.low.Substring(0, [Math]::Max(0, $o.low.LastIndexOf('\')))
    $k = $dir + '|' + $o.when
    if (-not $byKey.ContainsKey($k)) { $byKey[$k] = New-Object System.Collections.ArrayList }
    $null = $byKey[$k].Add($o)
}
foreach ($k in $byKey.Keys) {
    $grp = $byKey[$k]
    $names = @($grp | ForEach-Object { $_.name.ToLower() } | Sort-Object -Unique)
    if ($names.Count -lt 2) { continue }
    Add-Finding 'possible_rename' 'MEDIUM' ($names -join ' / ') $grp[0].path `
        $grp[0].when $grp[0].kind 'ShimCache' `
        ('same folder and same file mtime under ' + $names.Count + ' different names -' +
         ' a rename leaves exactly this trace (not proof on its own)') ''
}

# R8 - mtime copied from a system binary onto something outside System32 (timestomping).
# Windows Update stamps whole batches identically, which produced 39 hits on the clean host,
# so: only tier-1 binaries donate a stamp, and only staging-folder files can receive one.
$sysStamps = @{}
foreach ($o in $shim) {
    if (-not $o.when) { continue }
    if (-not (Has-Segment $o.low $SYSDIRS)) { continue }
    if ($CORE_SYSBIN -notcontains $o.name.ToLower()) { continue }
    $sysStamps[$o.when] = $o.name
}
foreach ($o in $shim) {
    if (-not $o.when) { continue }
    if (Has-Segment $o.low $SYSDIRS) { continue }
    # NOTE the parentheses around EVERY call: `if (Is-Self $x -or (Is-Trusted $x))` passes
    # '-or' and the next value as ARGUMENTS to Is-Self, so the rest of the condition is
    # silently dropped. Verified: the callee received 2 extra args. That bug had disabled
    # the trusted/installer filters entirely.
    if ((Is-Self $o.low) -or (Is-Trusted $o.low) -or (Is-Installer $o.low)) { continue }
    if (-not (Staging-Of $o.low)) { continue }
    if ($sysStamps.ContainsKey($o.when)) {
        Add-Finding 'timestamp_copied' 'MEDIUM' $o.name $o.path $o.when $o.kind 'ShimCache' `
            ('file mtime identical to the system binary ' + $sysStamps[$o.when]) ''
    }
}

# R9 - recon burst from Prefetch. Individually legitimate tools; the CLUSTER is the signal.
$rec = @()
foreach ($p in $pe) {
    if ($RECON -notcontains $p.name) { continue }
    $t = $null
    try { $t = [DateTime]::Parse($p.last) } catch { continue }
    $rec += [PSCustomObject]@{ name = $p.name; t = $t; runs = $p.runs }
}
$rec = @($rec | Sort-Object t)
if ($rec.Count -ge 4) {
    $i = 0
    while ($i -lt $rec.Count) {
        $j = $i; $tools = @{}
        while ($j -lt $rec.Count -and ($rec[$j].t - $rec[$i].t).TotalMinutes -le 15) {
            $tools[$rec[$j].name] = $true; $j++
        }
        if ($tools.Count -ge 4) {
            $span = [int]($rec[$j - 1].t - $rec[$i].t).TotalMinutes
            Add-Finding 'recon_burst' 'HIGH' (($tools.Keys | Sort-Object) -join ', ') '' `
                $rec[$i].t.ToString('yyyy-MM-dd HH:mm:ss') 'execution(prefetch)' 'Prefetch' `
                ($tools.Count.ToString() + ' recon tools within ' + $span + ' min') ''
            $i = $j
        } else { $i++ }
    }
}

# R10 - inbound remote access, straight from Prefetch execution times.
foreach ($p in $pe) {
    $why = $null
    if ($p.name -eq 'wsmprovhost.exe') { $why = 'INBOUND PowerShell Remoting was served on this host' }
    if ($p.name -eq 'rdpclip.exe')     { $why = 'RDP session clipboard - an interactive RDP session took place' }
    if ($p.name -eq 'psexesvc.exe')    { $why = 'PsExec service ran on this host' }
    if ($why) {
        Add-Finding 'remote_access' 'HIGH' $p.name '' $p.last 'execution(prefetch)' 'Prefetch' `
            ($why + ' (run count ' + $p.runs + ')') ''
    }
}

# ---------------------------------------------------------------- output ----
$order = @('HIGH','MEDIUM','LOW')
$all = @($FINDINGS | Sort-Object @{Expression={$order.IndexOf($_.severity)}}, rule, name)

$byRule = @{}
foreach ($f in $all) {
    if (-not $byRule.ContainsKey($f.rule)) { $byRule[$f.rule] = New-Object System.Collections.ArrayList }
    $null = $byRule[$f.rule].Add($f)
}

$L = New-Object System.Collections.ArrayList
$null = $L.Add('=================================================================')
$null = $L.Add(' EXECUTION ARTEFACT FINDINGS  (ShimCache / Amcache / Prefetch)')
$null = $L.Add(' generated by the DFIR collector - ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$null = $L.Add('=================================================================')
$null = $L.Add('')
$null = $L.Add('HOW TO READ THE TIMESTAMPS - this is where most mistakes are made:')
$null = $L.Add('  file_mtime(shimcache)  the FILE modification time. NOT an execution time.')
$null = $L.Add('                         On Win7+ ShimCache holds no execution time at all,')
$null = $L.Add('                         and an entry does not by itself prove execution.')
$null = $L.Add('  first_seen(amcache)    when the Amcache entry was written (~first seen).')
$null = $L.Add('  execution(prefetch)    a REAL execution time. Run counts are real too.')
$null = $L.Add('')
$null = $L.Add('NOTE: ShimCache is flushed to the SYSTEM hive only on reboot, so activity')
$null = $L.Add('      since the last reboot may be missing from it.')
$null = $L.Add('')
$null = $L.Add('TOTAL FINDINGS: ' + $all.Count)
foreach ($r in ($byRule.Keys | Sort-Object)) {
    $null = $L.Add(('  {0,-24} {1}' -f $r, $byRule[$r].Count))
}
if ($hosts.Keys.Count) {
    $null = $L.Add('')
    $null = $L.Add('*** OTHER HOSTS REFERENCED (investigate these too) ***')
    foreach ($h in ($hosts.Keys | Sort-Object)) { $null = $L.Add('    ' + $h) }
}

foreach ($r in ($byRule.Keys | Sort-Object)) {
    $items = $byRule[$r]
    $null = $L.Add('')
    $null = $L.Add('-----------------------------------------------------------------')
    $null = $L.Add(('[{0}]  {1} finding(s)' -f $r, $items.Count))
    $null = $L.Add('-----------------------------------------------------------------')
    $n = 0
    foreach ($f in $items) {
        if ($n -ge $MaxPerRule) {
            $null = $L.Add(('    ... and ' + ($items.Count - $n) + ' more (see the CSV)'))
            break
        }
        $null = $L.Add(('  [{0}] {1}' -f $f.severity, $f.name))
        if ($f.path)  { $null = $L.Add('        path : ' + $f.path) }
        if ($f.when)  { $null = $L.Add('        when : ' + $f.when + '   (' + $f.when_kind + ')') }
        if ($f.sha1)  { $null = $L.Add('        sha1 : ' + $f.sha1) }
        $null = $L.Add('        why  : ' + $f.detail + '   [' + $f.artifact + ']')
        $n++
    }
}
if ($all.Count -eq 0) {
    $null = $L.Add('')
    $null = $L.Add('No execution-artefact anomalies matched. This is a normal result on a')
    $null = $L.Add('clean machine and is NOT by itself proof that nothing happened.')
}

Set-Content -LiteralPath $OutFile -Value $L -Encoding ASCII
$all | Select-Object rule, severity, name, path, when, when_kind, artifact, detail, sha1 |
    Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding UTF8

'TOTAL|' + $all.Count
foreach ($r in ($byRule.Keys | Sort-Object)) { 'RULE|' + $r + '=' + $byRule[$r].Count }
'HOSTS|' + (($hosts.Keys | Sort-Object) -join ',')
'OUT|' + $OutFile
