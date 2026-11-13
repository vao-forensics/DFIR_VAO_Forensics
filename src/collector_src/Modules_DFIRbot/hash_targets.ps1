# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : hash_targets.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : SHA256/SHA1/MD5 hashing of selected files (READ-ONLY)
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
param(
    [string]$SuspectCsv = "",
    [string]$Drive      = "C",
    [string]$OutCsv     = "",
    [int]$MaxFiles      = 4000,
    [int]$MaxFileMB     = 512,
    [int]$MaxSeconds    = 300
)
# Hash exactly the files the MFT pass already FLAGGED (suspicious_files.csv), so the bot can
# check them against reputation databases. Hashing the whole volume is pointless: hours of
# I/O for noise. Everything here is bounded - file count, per-file size and a time budget -
# so this step can never turn into another runaway like the Telegram target did.
#
# Emits SHA256 + SHA1 + MD5 on purpose, because the databases disagree:
#   SHA-1   -> CIRCL/NSRL known-GOOD bloom filter
#   SHA-256 -> MalwareBazaar known-BAD
#   MD5     -> legacy sets (ClamAV and older hash sets)
# Works for a mounted image too: MFT paths are volume-relative, so they are prefixed with the
# chosen drive letter rather than assumed to be C:.
#
# ASCII-ONLY: PS 5.1 reading a BOM-less file breaks on non-ASCII literals.
# stdout: HASHED|n  SKIPPED|n  MB|n  TRUNC|0|1  OUT|<path>

if (-not $SuspectCsv) { 'HASHED|0'; 'SKIPPED|0'; 'MB|0'; 'TRUNC|0'; 'OUT|'; exit 0 }
if (-not (Test-Path $SuspectCsv)) { 'HASHED|0'; 'SKIPPED|0'; 'MB|0'; 'TRUNC|0'; 'OUT|'; exit 0 }
if (-not $OutCsv) { $OutCsv = Join-Path (Split-Path $SuspectCsv -Parent) 'hashes.csv' }

$drv = $Drive.TrimEnd(':')
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$maxBytes = [long]$MaxFileMB * 1MB

$sha256 = [System.Security.Cryptography.SHA256]::Create()
$sha1   = [System.Security.Cryptography.SHA1]::Create()
$md5    = [System.Security.Cryptography.MD5]::Create()

function Hex($bytes) { ($bytes | ForEach-Object { $_.ToString('x2') }) -join '' }

$rows = New-Object System.Collections.ArrayList
$hashed = 0; $skipped = 0; $trunc = 0
$bytesRead = [long]0
$seen = New-Object System.Collections.Generic.HashSet[string]

try {
    $items = Import-Csv $SuspectCsv -ErrorAction Stop
} catch {
    'HASHED|0'; 'SKIPPED|0'; 'MB|0'; 'TRUNC|1'; 'OUT|'; exit 0
}

foreach ($it in $items) {
    if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $trunc = 1; break }
    if ($hashed -ge $MaxFiles) { $trunc = 1; break }

    $rel = [string]$it.Path
    if (-not $rel) { continue }
    # MFT paths are volume-relative ("\Users\x\...") - bind them to the collected drive
    $full = if ($rel -match '^[A-Za-z]:') { $rel } else { $drv + ':' + $rel }
    if (-not $seen.Add($full.ToLowerInvariant())) { continue }   # same file, several categories

    try {
        $fi = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    } catch { $skipped++; continue }                              # deleted / unreadable
    if ($fi.PSIsContainer) { continue }
    if ($fi.Length -gt $maxBytes) { $skipped++; continue }

    try {
        $fs = [System.IO.File]::Open($full, 'Open', 'Read', 'ReadWrite')
        $buf = New-Object byte[] 1048576
        $sha256.Initialize(); $sha1.Initialize(); $md5.Initialize()
        while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
            [void]$sha256.TransformBlock($buf, 0, $n, $null, 0)
            [void]$sha1.TransformBlock($buf, 0, $n, $null, 0)
            [void]$md5.TransformBlock($buf, 0, $n, $null, 0)
            $bytesRead += $n
        }
        [void]$sha256.TransformFinalBlock($buf, 0, 0)
        [void]$sha1.TransformFinalBlock($buf, 0, 0)
        [void]$md5.TransformFinalBlock($buf, 0, 0)
        $fs.Close()

        [void]$rows.Add([PSCustomObject]@{
            Path      = $full
            FileName  = $fi.Name
            SizeBytes = $fi.Length
            SHA256    = Hex $sha256.Hash
            SHA1      = Hex $sha1.Hash
            MD5       = Hex $md5.Hash
            Category  = [string]$it.Category
            Note      = [string]$it.Note
            Modified  = $fi.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            Source    = 'targeted'
        })
        $hashed++
    } catch { $skipped++ }
}

try {
    if ($rows.Count -eq 0) {
        # still write a header so the bot always finds a well-formed table
        'Path,FileName,SizeBytes,SHA256,SHA1,MD5,Category,Note,Modified,Source' |
            Out-File -FilePath $OutCsv -Encoding utf8
    } else {
        $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv -ErrorAction Stop
    }
} catch {}

'HASHED|' + $hashed
'SKIPPED|' + $skipped
'MB|' + [math]::Round($bytesRead / 1MB, 1)
'TRUNC|' + $trunc
'OUT|' + $OutCsv
