# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : collect_motw.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : collect Zone.Identifier provenance marks (READ-ONLY)
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
# collect_motw.ps1 - MOTW / Zone.Identifier collector for the DFIR bot
# Scans a drive's user-download locations for files carrying the :Zone.Identifier
# NTFS ADS and emits a CSV matching the bot contract (docs/MOTW_INTEGRATION.md):
#   columns: Path, ZoneId, HostUrl, ReferrerUrl, Timestamp
# Output goes to <OutDir>\motw_zone_identifier.csv  (bot reads folder 'motw' / *zone_identifier*).
#
# Usage: powershell -ExecutionPolicy Bypass -File collect_motw.ps1 -Drive C -OutDir "C:\...\output\motw"
param(
    [Parameter(Mandatory=$true)][string]$Drive,
    [Parameter(Mandatory=$true)][string]$OutDir
)
$ErrorActionPreference = 'SilentlyContinue'
$Drive = $Drive.TrimEnd(':')
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outCsv = Join-Path $OutDir 'motw_zone_identifier.csv'

# High-signal locations where downloaded files (and their MOTW) live. Bounded for speed.
$rel = @(
    'Downloads', 'Desktop', 'Documents',
    'AppData\Local\Temp',
    'AppData\Local\Microsoft\Windows\INetCache\IE',
    'AppData\Roaming\Microsoft\Windows\Recent'
)
$roots = @()
Get-ChildItem "$Drive`:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    foreach ($r in $rel) { $p = Join-Path $_.FullName $r; if (Test-Path $p) { $roots += $p } }
}

$rows = New-Object System.Collections.Generic.List[object]
foreach ($root in $roots) {
    Get-ChildItem -Path $root -Recurse -File -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Length -lt 524288000 } | ForEach-Object {
        $f = $_
        $zi = Get-Content -LiteralPath $f.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
        if ($zi) {
            $text = ($zi -join "`n")
            $zid  = ([regex]::Match($text, '(?im)^\s*ZoneId\s*=\s*(.+?)\s*$')).Groups[1].Value
            $host_= ([regex]::Match($text, '(?im)^\s*HostUrl\s*=\s*(.+?)\s*$')).Groups[1].Value
            $ref  = ([regex]::Match($text, '(?im)^\s*ReferrerUrl\s*=\s*(.+?)\s*$')).Groups[1].Value
            # Ingest only rows with provenance (HostUrl or ReferrerUrl), per the contract.
            if ($host_ -or $ref) {
                $rows.Add([pscustomobject]@{
                    Path        = $f.FullName
                    ZoneId      = $zid
                    HostUrl     = $host_
                    ReferrerUrl = $ref
                    Timestamp   = $f.LastWriteTimeUtc.ToString('o')
                })
            }
        }
    }
}

if ($rows.Count -gt 0) {
    $rows | Export-Csv -LiteralPath $outCsv -NoTypeInformation -Encoding UTF8
    Write-Output ("MOTW: wrote {0} rows -> {1}" -f $rows.Count, $outCsv)
} else {
    # still emit a header-only CSV so the bot's folder routing is consistent
    'Path,ZoneId,HostUrl,ReferrerUrl,Timestamp' | Set-Content -LiteralPath $outCsv -Encoding UTF8
    Write-Output "MOTW: no Zone.Identifier provenance found (empty CSV written)"
}
