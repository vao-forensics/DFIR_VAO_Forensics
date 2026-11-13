# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : hunt_encrypted.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : search for encrypted containers and files (READ-ONLY)
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
param(
    [string]$Drive = "C",
    [string]$OutCsv = "$env:TEMP\_dfir_encfiles.csv",
    [int]$MaxSeconds = 240,
    [int]$MinContainerMB = 5,
    [int]$Deep = 0,
    [string]$ScanRoot = ""
)
# Hunt DORMANT encryption on disk: encrypted containers, encrypted archives/documents and
# encryption-tool artifacts. check_encryption.ps1 finds ACTIVE/mounted encryption; this finds
# the files sitting on the disk. Same ground as Magnet EDD / Elcomsoft EEDH / Passware
# Encryption Analyzer, but ours - no third-party binary, no licence, our own output format.
#
# ASCII-ONLY on purpose: PS 5.1 reading a BOM-less file breaks on non-ASCII literals.
# stdout contract: CONT|n  ARCH|n  DOC|n  TOOL|n  TRUNC|0|1  SCANNED|n  CSV|<path>

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$rows = New-Object System.Collections.ArrayList
$truncated = 0
$scanned = 0

function Add-Hit($cat, $path, $size, $ent, $reason) {
    [void]$rows.Add([PSCustomObject]@{
        Category = $cat
        Path     = $path
        SizeMB   = [math]::Round($size / 1MB, 2)
        Entropy  = $ent
        Reason   = $reason
    })
}

# Extensions that are UNAMBIGUOUSLY tied to encryption tools / containers.
# Deliberately NOT here (proven false positives on a real host):
#   .vc  -> also a Visual C nmake makefile (tcl\nmake\rules.vc, targets.vc)
#   .enc -> also Tcl encoding tables (cp936.enc, big5.enc; entropy ~3.5) - see $weakExt
$toolExt = @{
    '.hc' = 'VeraCrypt container'; '.tc' = 'TrueCrypt container'
    '.kdbx' = 'KeePass database'; '.kdb' = 'KeePass database'
    '.axx' = 'AxCrypt file'; '.gpg' = 'GnuPG file'; '.pgp' = 'PGP file'
    '.pfx' = 'PKCS#12 key store'; '.p12' = 'PKCS#12 key store'
    '.luks' = 'LUKS volume'
    '.bc' = 'BestCrypt container'; '.jbc' = 'BestCrypt container'
    '.cryptomator' = 'Cryptomator vault'; '.sdsk' = 'SecureDoc container'
}
# Generic extensions: only count them when the CONTENT actually looks encrypted.
$weakExt = @{ '.enc' = 'encrypted file'; '.aes' = 'AES file' }
# High-entropy by nature -> never a container candidate (kills the obvious false positives).
$skipExt = @(
    '.zip','.7z','.rar','.gz','.bz2','.xz','.cab','.msi','.iso','.jpg','.jpeg','.png','.gif',
    '.bmp','.webp','.mp3','.mp4','.avi','.mkv','.mov','.wmv','.flac','.m4a','.pdf','.docx',
    '.xlsx','.pptx','.exe','.dll','.sys','.cat','.pak','.vmdk','.vhd','.vhdx','.vdi','.ost',
    '.pst','.edb','.wim','.esd','.dmp','.bin.gz','.crx','.jar','.apk','.woff','.woff2'
)
# First-bytes magic of well-known formats. A container has NO magic - that is the point.
$magics = @(
    @(0x50,0x4B), @(0x52,0x61,0x72,0x21), @(0x37,0x7A,0xBC,0xAF), @(0x1F,0x8B),
    @(0x89,0x50,0x4E,0x47), @(0xFF,0xD8,0xFF), @(0x47,0x49,0x46,0x38),
    @(0x25,0x50,0x44,0x46), @(0x4D,0x5A), @(0x4D,0x53,0x43,0x46),
    @(0xD0,0xCF,0x11,0xE0), @(0x53,0x51,0x4C,0x69), @(0x72,0x65,0x67,0x66),
    @(0x49,0x44,0x33), @(0x42,0x4D), @(0x7F,0x45,0x4C,0x46), @(0x00,0x01,0x00,0x00)
)

function Test-Magic([byte[]]$head) {
    foreach ($m in $magics) {
        $ok = $true
        for ($i = 0; $i -lt $m.Count; $i++) {
            if ($head.Count -le $i -or $head[$i] -ne $m[$i]) { $ok = $false; break }
        }
        if ($ok) { return $true }
    }
    # mp4/mov: 'ftyp' at offset 4
    if ($head.Count -ge 8 -and $head[4] -eq 0x66 -and $head[5] -eq 0x74 -and
        $head[6] -eq 0x79 -and $head[7] -eq 0x70) { return $true }
    return $false
}

function Get-SampleEntropy($path, $size) {
    # Sample 3 x 32KB (start / middle / end) instead of reading whole multi-GB files.
    try {
        $fs = [System.IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        $chunk = 32768
        $counts = New-Object 'int[]' 256
        $total = 0
        $offsets = @(0)
        if ($size -gt ($chunk * 3)) { $offsets = @(0, [long]($size / 2), [long]($size - $chunk)) }
        foreach ($off in $offsets) {
            $fs.Seek($off, 'Begin') | Out-Null
            $buf = New-Object byte[] $chunk
            $n = $fs.Read($buf, 0, $chunk)
            for ($i = 0; $i -lt $n; $i++) { $counts[$buf[$i]]++ }
            $total += $n
        }
        $fs.Close()
        if ($total -eq 0) { return -1 }
        $e = 0.0
        foreach ($c in $counts) {
            if ($c -gt 0) { $p = $c / $total; $e -= $p * [math]::Log($p, 2) }
        }
        return [math]::Round($e, 3)
    } catch { return -1 }
}

function Get-Head($path, $n) {
    try {
        $fs = [System.IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        $buf = New-Object byte[] $n
        $r = $fs.Read($buf, 0, $n)
        $fs.Close()
        if ($r -lt $n) { return $buf[0..([math]::Max($r - 1, 0))] }
        return $buf
    } catch { return @() }
}

# ---------------- scope ----------------
$roots = @()
$d = $Drive.TrimEnd(':') + ':\'
foreach ($sub in @('Users', 'ProgramData', 'Temp')) {
    $p = Join-Path $d $sub
    if (Test-Path $p) { $roots += $p }
}
if ($Deep -eq 1) { $roots = @($d) }
if ($ScanRoot) { $roots = @($ScanRoot) }   # test/override hook
# always look at the drive root itself (containers are often dropped there)
$rootFiles = @()
if (-not $ScanRoot) {
    try { $rootFiles = Get-ChildItem $d -File -Force -ErrorAction SilentlyContinue } catch {}
}

# NOTE: AppData\Local\Temp is deliberately NOT skipped - containers and encrypted archives
# get stashed there. Only genuinely useless high-volume caches are excluded.
$skipDirRe = '\\(Windows\\(WinSxS|Installer|assembly|servicing)|node_modules|' +
             'Program Files\\WindowsApps|AppData\\Local\\Packages\\[^\\]+\\LocalCache|' +
             'AppData\\Local\\Microsoft\\Windows\\INetCache)'

$files = New-Object System.Collections.ArrayList
foreach ($f in $rootFiles) { [void]$files.Add($f) }
foreach ($r in $roots) {
    if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $truncated = 1; break }
    try {
        Get-ChildItem $r -Recurse -File -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $truncated = 1; return }
                if ($_.FullName -notmatch $skipDirRe) { [void]$files.Add($_) }
            }
    } catch {}
}

# ---------------- classify ----------------
foreach ($f in $files) {
    if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $truncated = 1; break }
    $scanned++
    $ext = $f.Extension.ToLower()

    # 1) encryption-tool artifacts (cheap, extension only)
    if ($toolExt.ContainsKey($ext)) {
        Add-Hit 'tool_artifact' $f.FullName $f.Length '' $toolExt[$ext]
        continue
    }
    # 1b) generic extensions must PROVE they are encrypted (kills Tcl .enc tables)
    if ($weakExt.ContainsKey($ext)) {
        if ($f.Length -ge 4096) {
            $we = Get-SampleEntropy $f.FullName $f.Length
            if ($we -ge 7.5) {
                Add-Hit 'tool_artifact' $f.FullName $f.Length $we ($weakExt[$ext] + ' (entropy ' + $we + ')')
            }
        }
        continue
    }
    # 1c) PGP armored text: only when the header really says so
    if ($ext -eq '.asc' -or $ext -eq '.sig') {
        $h = Get-Head $f.FullName 64
        if ($h.Count -gt 0) {
            $s = [System.Text.Encoding]::ASCII.GetString($h)
            if ($s -match 'BEGIN PGP') {
                Add-Hit 'tool_artifact' $f.FullName $f.Length '' 'PGP armored block'
            }
        }
        continue
    }

    # 2) encrypted ZIP (general purpose bit 0 of the local file header)
    if ($ext -eq '.zip' -or $ext -eq '.docx' -or $ext -eq '.xlsx' -or $ext -eq '.pptx') {
        $h = Get-Head $f.FullName 10
        if ($h.Count -ge 8 -and $h[0] -eq 0x50 -and $h[1] -eq 0x4B -and (($h[6] -band 0x01) -eq 1)) {
            Add-Hit 'encrypted_archive' $f.FullName $f.Length '' 'ZIP with encryption flag set'
        }
        continue
    }
    # 2b) encrypted RAR4 (header flag 0x0004)
    if ($ext -eq '.rar') {
        $h = Get-Head $f.FullName 24
        if ($h.Count -ge 24 -and $h[0] -eq 0x52 -and $h[1] -eq 0x61 -and $h[2] -eq 0x72 -and $h[3] -eq 0x21) {
            if (($h[10] -band 0x04) -eq 4) {
                Add-Hit 'encrypted_archive' $f.FullName $f.Length '' 'RAR with password flag'
            }
        }
        continue
    }

    # 3) encrypted Office (OLE CFB) / PDF
    if ($ext -eq '.doc' -or $ext -eq '.xls' -or $ext -eq '.ppt' -or $ext -eq '.msg') {
        $h = Get-Head $f.FullName 8
        if ($h.Count -ge 4 -and $h[0] -eq 0xD0 -and $h[1] -eq 0xCF -and $h[2] -eq 0x11 -and $h[3] -eq 0xE0) {
            try {
                $raw = [System.IO.File]::ReadAllBytes($f.FullName)
                $s = [System.Text.Encoding]::Unicode.GetString($raw[0..([math]::Min($raw.Length - 1, 65535))])
                if ($s -match 'EncryptedPackage|EncryptionInfo') {
                    Add-Hit 'encrypted_document' $f.FullName $f.Length '' 'OLE container with EncryptedPackage'
                }
            } catch {}
        }
        continue
    }
    if ($ext -eq '.pdf') {
        try {
            $raw = Get-Head $f.FullName 4096
            $s = [System.Text.Encoding]::ASCII.GetString($raw)
            if ($s -match '/Encrypt') {
                Add-Hit 'encrypted_document' $f.FullName $f.Length '' 'PDF with /Encrypt'
            }
        } catch {}
        continue
    }

    # 4) container candidate: big, 512-aligned, no magic, near-maximum entropy
    if ($f.Length -lt ($MinContainerMB * 1MB)) { continue }
    if ($skipExt -contains $ext) { continue }
    if (($f.Length % 512) -ne 0) { continue }
    $head = Get-Head $f.FullName 16
    if ($head.Count -lt 16) { continue }
    if (Test-Magic $head) { continue }
    $ent = Get-SampleEntropy $f.FullName $f.Length
    if ($ent -ge 7.95) {
        $why = 'no file signature, 512-aligned, entropy ' + $ent + ' (VeraCrypt/TrueCrypt-like)'
        Add-Hit 'container_candidate' $f.FullName $f.Length $ent $why
    }
}

$cont = @($rows | Where-Object { $_.Category -eq 'container_candidate' }).Count
$arch = @($rows | Where-Object { $_.Category -eq 'encrypted_archive' }).Count
$doc  = @($rows | Where-Object { $_.Category -eq 'encrypted_document' }).Count
$tool = @($rows | Where-Object { $_.Category -eq 'tool_artifact' }).Count

try {
    $dir = Split-Path $OutCsv -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ($rows.Count -eq 0) { Add-Hit 'None' '-' 0 '' 'no encrypted files or containers found' }
    $rows | Sort-Object Category, @{Expression = 'SizeMB'; Descending = $true } |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv -ErrorAction Stop
} catch {}

'CONT|' + $cont
'ARCH|' + $arch
'DOC|' + $doc
'TOOL|' + $tool
'TRUNC|' + $truncated
'SCANNED|' + $scanned
'CSV|' + $OutCsv
