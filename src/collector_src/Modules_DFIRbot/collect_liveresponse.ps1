# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : collect_liveresponse.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : live snapshot: processes, network, services (READ-ONLY)
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
param(
    [string]$OutDir = "",
    [int]$MaxSeconds = 180
)
# Live snapshot of the RUNNING system: what is executing right now and who it talks to.
#
# WHY THIS EXISTS: the disk tells us what ran at some point (Prefetch, Amcache, ShimCache).
# It does NOT tell us what is running NOW and which process holds a connection. For an
# incident where the malicious process is still alive, that is the decisive evidence.
#
# REPLACES A THIRD-PARTY TOOL: CurrPorts/cports shows which process owns a connection. We
# already captured OwningProcess (the PID); everything else is a PID->process join, so this
# is written with built-in APIs instead of shipping another binary. A NirSoft utility once
# hung the whole collector, so avoiding one is a feature.
#
# LIVE ONLY. On a mounted image these objects belong to the EXAMINER's workstation.
# ASCII-ONLY: PS 5.1 reading a BOM-less file breaks on non-ASCII literals.
# stdout: PROC|n  CONN|n  PIPE|n  SVC|n  SESS|n  TRUNC|0|1

if (-not $OutDir) { 'PROC|0'; 'CONN|0'; 'PIPE|0'; 'SVC|0'; 'SESS|0'; 'TRUNC|0'; exit 0 }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$trunc = 0
$counts = @{ PROC = 0; CONN = 0; PIPE = 0; SVC = 0; SESS = 0 }

function Save($rows, $name, $key) {
    try {
        if ($rows) {
            $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir $name)
            $script:counts[$key] = @($rows).Count
        }
    } catch {}
}

# ---------------- processes: tree + command line + signature ----------------
# The command line is the single most valuable field here: a phishing chain shows up as
# winword.exe -> cmd.exe -> powershell -enc <base64> without any further analysis.
$procMap = @{}
try {
    $raw = Get-CimInstance Win32_Process -ErrorAction Stop |
           Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
    foreach ($p in $raw) { $procMap[[int]$p.ProcessId] = $p }

    $rows = foreach ($p in $raw) {
        if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $trunc = 1; break }
        $parent = $procMap[[int]$p.ParentProcessId]
        $sig = ''
        if ($p.ExecutablePath) {
            try { $sig = (Get-AuthenticodeSignature -LiteralPath $p.ExecutablePath -ErrorAction Stop).Status } catch { $sig = 'Unknown' }
        }
        [PSCustomObject]@{
            PID          = $p.ProcessId
            ParentPID    = $p.ParentProcessId
            Name         = $p.Name
            ParentName   = if ($parent) { $parent.Name } else { '' }
            Path         = $p.ExecutablePath
            CommandLine  = $p.CommandLine
            Started      = $p.CreationDate
            Signature    = $sig
        }
    }
    Save $rows 'processes.csv' 'PROC'
} catch {}

# ---------------- network: TCP + UDP WITH process attribution ----------------
try {
    $conns = @()
    try {
        $conns += Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            $p = $procMap[[int]$_.OwningProcess]
            [PSCustomObject]@{
                Proto         = 'TCP'
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort    = $_.RemotePort
                State         = $_.State
                PID           = $_.OwningProcess
                ProcessName   = if ($p) { $p.Name } else { '' }
                ProcessPath   = if ($p) { $p.ExecutablePath } else { '' }
                CommandLine   = if ($p) { $p.CommandLine } else { '' }
            }
        }
    } catch {}
    try {
        $conns += Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            $p = $procMap[[int]$_.OwningProcess]
            [PSCustomObject]@{
                Proto         = 'UDP'
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                RemoteAddress = ''
                RemotePort    = ''
                State         = ''
                PID           = $_.OwningProcess
                ProcessName   = if ($p) { $p.Name } else { '' }
                ProcessPath   = if ($p) { $p.ExecutablePath } else { '' }
                CommandLine   = if ($p) { $p.CommandLine } else { '' }
            }
        }
    } catch {}
    Save $conns 'connections.csv' 'CONN'
} catch {}

# ---------------- named pipes ----------------
# C2 frameworks create characteristic named pipes; the list is small and cheap to take.
try {
    $pipes = Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue |
             Select-Object @{n = 'Pipe'; e = { $_.Name } }
    Save $pipes 'named_pipes.csv' 'PIPE'
} catch {}

# ---------------- services with binary path + state ----------------
try {
    $svc = Get-CimInstance Win32_Service -ErrorAction Stop |
           Select-Object Name, DisplayName, State, StartMode, PathName, ProcessId, StartName
    Save $svc 'services.csv' 'SVC'
} catch {}

# ---------------- logged-on sessions and SMB ----------------
try {
    $sess = @()
    try {
        $sess += Get-CimInstance Win32_LoggedOnUser -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Kind = 'LoggedOnUser'; Detail = $_.Antecedent }
        }
    } catch {}
    try {
        $sess += Get-SmbSession -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Kind = 'SmbSession'; Detail = ($_.ClientComputerName.ToString() + ' / ' + $_.ClientUserName) }
        }
    } catch {}
    try {
        $sess += Get-SmbShare -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Kind = 'SmbShare'; Detail = ($_.Name + ' -> ' + $_.Path) }
        }
    } catch {}
    Save $sess 'sessions.csv' 'SESS'
} catch {}

if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $trunc = 1 }

'PROC|' + $counts.PROC
'CONN|' + $counts.CONN
'PIPE|' + $counts.PIPE
'SVC|' + $counts.SVC
'SESS|' + $counts.SESS
'TRUNC|' + $trunc
