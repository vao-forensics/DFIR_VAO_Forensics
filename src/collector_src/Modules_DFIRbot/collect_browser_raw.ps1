# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : collect_browser_raw.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : copy browser databases (READ-ONLY)
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
param(
    [string]$InDir  = "",
    [string]$RawDir = "",
    [int]$MaxFileMB = 300,
    [int]$BudgetMB  = 1500
)
# Copy the RAW browser databases KAPE collected into _raw\browsers\<user>\<browser>\ of the
# OUTPUT archive, so the BOT can parse them itself (vao_parser_browser). Today the raw DBs
# only exist in the INPUT archive, which the bot normally never receives.
#
# TWO THINGS THAT MATTER:
#  1. WAL sidecars (-wal / -journal / -shm) MUST travel with the database. Without them a
#     Chromium/Firefox DB reads back STALE - the newest history is still in the WAL, and the
#     newest history is exactly the evidence that matters.
#  2. A size cap. The stock Telegram target once dragged 382 GB into a triage; browser
#     profiles can hold huge Favicons/Cache files, so cap per-file and total.
#
# ASCII-ONLY: PS 5.1 reading a BOM-less file breaks on non-ASCII literals.
# stdout: FILES|n  MB|n  USERS|n  SKIP|n  TRUNC|0|1

if (-not $InDir -or -not $RawDir) { 'FILES|0'; 'MB|0'; 'USERS|0'; 'SKIP|0'; 'TRUNC|0'; exit 0 }

# Evidence files only - no caches, no favicons (large and low value).
$wanted = @(
    'history', 'web data', 'login data', 'login data for account', 'cookies',
    'bookmarks', 'preferences', 'secure preferences', 'shortcuts', 'top sites',
    'network action predictor', 'visited links',
    'places.sqlite', 'formhistory.sqlite', 'cookies.sqlite', 'downloads.sqlite',
    'permissions.sqlite', 'content-prefs.sqlite', 'logins.json', 'prefs.js',
    'sessionstore.jsonlz4', 'search.json.mozlz4'
)
# sidecars that must follow their parent database
$sidecarSuffix = @('-wal', '-shm', '-journal')

$browserHints = @{
    'chrome' = 'Chrome'; 'chromium' = 'Chromium'; 'edge' = 'Edge'; 'brave' = 'Brave'
    'opera' = 'Opera'; 'vivaldi' = 'Vivaldi'; 'yandex' = 'Yandex'; 'coccoc' = 'CocCoc'
    'arc' = 'Arc'; '360' = '360Browser'; 'firefox' = 'Firefox'; 'waterfox' = 'Waterfox'
    'librewolf' = 'LibreWolf'; 'tor browser' = 'TorBrowser'; 'mozilla' = 'Firefox'
    'qqbrowser' = 'QQBrowser'; 'puffin' = 'Puffin'
}

function Get-Browser($path) {
    $l = $path.ToLowerInvariant()
    foreach ($k in $browserHints.Keys) { if ($l.Contains('\' + $k)) { return $browserHints[$k] } }
    return 'Other'
}

function Get-User($path) {
    # take the segment AFTER the LAST '\users\' - the working dir itself can live under
    # C:\Users, and splitting on the FIRST occurrence names every file after the wrong user.
    $l = $path.ToLowerInvariant()
    $i = $l.LastIndexOf('\users\')
    if ($i -lt 0) { return 'unknown' }
    $rest = $path.Substring($i + 7)
    $j = $rest.IndexOf('\')
    if ($j -lt 0) { return 'unknown' }
    return $rest.Substring(0, $j)
}

$files = 0; $bytes = [long]0; $skipped = 0; $trunc = 0
$users = New-Object System.Collections.Generic.HashSet[string]
$maxFile = [long]$MaxFileMB * 1MB
$budget = [long]$BudgetMB * 1MB

try {
    $all = Get-ChildItem $InDir -Recurse -File -Force -ErrorAction SilentlyContinue
    foreach ($f in $all) {
        $n = $f.Name.ToLowerInvariant()
        $base = $n
        foreach ($s in $sidecarSuffix) { if ($base.EndsWith($s)) { $base = $base.Substring(0, $base.Length - $s.Length) } }
        if ($wanted -notcontains $base) { continue }

        if ($f.Length -gt $maxFile) { $skipped++; continue }
        if ($bytes + $f.Length -gt $budget) { $trunc = 1; break }

        $u = Get-User $f.FullName
        $b = Get-Browser $f.DirectoryName
        $dst = Join-Path (Join-Path $RawDir $u) $b
        if (-not (Test-Path $dst)) { New-Item -ItemType Directory -Path $dst -Force | Out-Null }

        # keep the profile folder name (Default / Profile 1 ...) so multiple profiles do not collide
        $prof = Split-Path $f.DirectoryName -Leaf
        $target = Join-Path $dst ($prof + '__' + $f.Name)
        try {
            Copy-Item $f.FullName $target -Force -ErrorAction Stop
            $files++; $bytes += $f.Length
            [void]$users.Add($u)
        } catch { $skipped++ }
    }
} catch {}

'FILES|' + $files
'MB|' + [math]::Round($bytes / 1MB, 1)
'USERS|' + $users.Count
'SKIP|' + $skipped
'TRUNC|' + $trunc
