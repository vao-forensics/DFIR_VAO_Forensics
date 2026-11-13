# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : check_encryption.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : check disk encryption state (READ-ONLY)
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
param(
    [string]$OutCsv = "$env:TEMP\_dfir_encryption.csv"
)
# Detect disk encryption BEFORE collection so the operator knows what they are dealing with:
#  - BitLocker (per volume, incl. method + conversion state)
#  - VeraCrypt / TrueCrypt (process, driver, service, container-mounted volumes)
#  - third-party full-disk encryption (ESET/Sophos/Symantec/McAfee/CheckPoint/DiskCryptor...)
#  - raw MBR/boot-sector signatures (catches what WMI cannot: pre-boot FDE loaders)
# Same ground Magnet's free Encrypted Disk Detector covers, with no third-party binary.
#
# ASCII-ONLY on purpose: PS 5.1 reading a BOM-less file breaks on non-ASCII literals.
# Ukrainian UX lives in the .bat; this script emits machine-readable "KEY|value" lines.
#
# stdout contract (one per line): BL|..  VC|..  FDE|..  RAW|..  RISK|NONE|MED|HIGH  CSV|<path>

$rows = New-Object System.Collections.ArrayList

function Add-Row($type, $target, $status, $method, $details) {
    [void]$rows.Add([PSCustomObject]@{
        Type = $type; Target = $target; Status = $status; Method = $method; Details = $details
    })
}

# ---------------- BitLocker ----------------
$blParts = @()
$blActive = $false
try {
    $methods = @{
        0 = 'None'; 1 = 'AES128+Diffuser'; 2 = 'AES256+Diffuser'; 3 = 'AES128';
        4 = 'AES256'; 5 = 'HardwareEncryption'; 6 = 'XTS-AES128'; 7 = 'XTS-AES256'
    }
    $conv = @{
        0 = 'FullyDecrypted'; 1 = 'FullyEncrypted'; 2 = 'EncryptionInProgress';
        3 = 'DecryptionInProgress'; 4 = 'EncryptionPaused'; 5 = 'DecryptionPaused'
    }
    $vols = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' `
            -ClassName Win32_EncryptableVolume -ErrorAction Stop
    foreach ($v in $vols) {
        $dl = $v.DriveLetter
        if (-not $dl) { $dl = '(no letter)' }
        $on = ($v.ProtectionStatus -eq 1)
        $m = $methods[[int]$v.EncryptionMethod]
        if (-not $m) { $m = 'Unknown' }
        $c = $conv[[int]$v.ConversionStatus]
        if (-not $c) { $c = 'Unknown' }
        $st = 'OFF'
        if ($on) { $st = 'ON'; $blActive = $true; $blParts += ($dl + ' ON (' + $m + ')') }
        elseif ([int]$v.ConversionStatus -ne 0) { $st = 'PARTIAL'; $blParts += ($dl + ' ' + $c) }
        Add-Row 'BitLocker' $dl $st $m $c
    }
} catch {
    Add-Row 'BitLocker' '-' 'UNKNOWN' '' 'WMI namespace unavailable (Home edition or service off)'
}
if ($blParts.Count -gt 0) { $BL = ($blParts -join ', ') } else { $BL = 'not detected' }

# ---------------- VeraCrypt / TrueCrypt ----------------
$vcHits = @()
foreach ($n in @('VeraCrypt', 'VeraCrypt-x64', 'TrueCrypt', 'VeraCryptExpander')) {
    try {
        if (Get-Process -Name $n -ErrorAction SilentlyContinue) {
            $vcHits += ('process ' + $n)
            Add-Row 'VeraCrypt' $n 'RUNNING' '' 'process is running'
        }
    } catch {}
}
foreach ($n in @('veracrypt', 'truecrypt')) {
    try {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($s) {
            $vcHits += ('service ' + $n + '=' + $s.Status)
            Add-Row 'VeraCrypt' $n ([string]$s.Status) '' 'kernel service/driver present'
        }
    } catch {}
    $drv = Join-Path $env:SystemRoot ('System32\drivers\' + $n + '.sys')
    if (Test-Path $drv) {
        $vcHits += ('driver ' + $n + '.sys')
        Add-Row 'VeraCrypt' ($n + '.sys') 'PRESENT' '' $drv
    }
}
# Container/virtual mounts: a volume that has a drive letter but no backing partition
# (VeraCrypt container, mounted VHD, ImDisk...). Strong hint that data is unlocked NOW.
try {
    $partLetters = @(Get-Partition -ErrorAction Stop |
                     Where-Object { $_.DriveLetter } | ForEach-Object { [string]$_.DriveLetter })
    $volLetters = @(Get-Volume -ErrorAction Stop |
                    Where-Object { $_.DriveLetter -and $_.DriveType -ne 'CD-ROM' } |
                    ForEach-Object { [string]$_.DriveLetter })
    foreach ($l in $volLetters) {
        if ($partLetters -notcontains $l) {
            $vcHits += ('mounted ' + $l + ':')
            Add-Row 'VirtualVolume' ($l + ':') 'MOUNTED' '' 'volume with no backing partition (container/VHD/VeraCrypt)'
        }
    }
} catch {}
if ($vcHits.Count -gt 0) { $VC = ($vcHits -join ', ') } else { $VC = 'not detected' }

# ---------------- third-party full-disk encryption ----------------
$fdeMap = @{
    'eefdc|esetfde|ESET Full Disk'      = 'ESET Full Disk Encryption'
    'SGN|SafeGuard|Utimaco'             = 'Sophos/Utimaco SafeGuard'
    'PGPdisk|PGPsdk|SymEFA|EEDService|Symantec Endpoint Encryption' = 'Symantec/PGP Encryption'
    'MfeEpeSrv|MfeEpeHost|McAfee Drive' = 'McAfee/Trellix Drive Encryption'
    'CPDiskManager|Pointsec|Check Point Full Disk' = 'Check Point Full Disk Encryption'
    'dcrypt'                            = 'DiskCryptor'
    'BestCrypt|bcfsfltr'                = 'BestCrypt'
    'WinMagic|SecureDoc'                = 'WinMagic SecureDoc'
}
$fdeHits = @()
try {
    $svcs = Get-CimInstance Win32_Service -ErrorAction Stop |
            Select-Object Name, DisplayName, State, PathName
    foreach ($k in $fdeMap.Keys) {
        $m = $svcs | Where-Object { $_.Name -match $k -or $_.DisplayName -match $k }
        if ($m) {
            foreach ($x in $m) {
                $fdeHits += $fdeMap[$k]
                Add-Row 'ThirdPartyFDE' $fdeMap[$k] ([string]$x.State) '' ($x.Name + ' / ' + $x.DisplayName)
            }
        }
    }
} catch {}
$fdeHits = $fdeHits | Select-Object -Unique
if ($fdeHits.Count -gt 0) { $FDE = ($fdeHits -join ', ') } else { $FDE = 'not detected' }

# ---------------- raw boot-sector signatures ----------------
# Reads only the first 512 bytes of each physical disk. Catches pre-boot FDE loaders that
# leave a marker (BitLocker '-FVE-FS-', VeraCrypt/TrueCrypt boot loader strings).
$rawHits = @()
try {
    $disks = Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Select-Object -ExpandProperty DeviceID
    foreach ($d in $disks) {
        try {
            $fs = New-Object System.IO.FileStream($d, [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $buf = New-Object byte[] 512
            [void]$fs.Read($buf, 0, 512)
            $fs.Close()
            $txt = [System.Text.Encoding]::ASCII.GetString($buf)
            $sig = $null
            if ($txt -match '-FVE-FS-')            { $sig = 'BitLocker (-FVE-FS-)' }
            elseif ($txt -match 'VeraCrypt')        { $sig = 'VeraCrypt boot loader' }
            elseif ($txt -match 'TrueCrypt')        { $sig = 'TrueCrypt boot loader' }
            elseif ($txt -match 'LUKS')             { $sig = 'LUKS (Linux)' }
            elseif ($txt -match 'SafeBoot|Pointsec|SecureDoc') { $sig = 'third-party pre-boot FDE' }
            if ($sig) {
                # NOTE: no '>' in this string - the .bat echoes it, and '>' would redirect.
                $rawHits += ($d + ' : ' + $sig)
                Add-Row 'BootSector' $d 'SIGNATURE' '' $sig
            }
        } catch {}
    }
} catch {}
if ($rawHits.Count -gt 0) { $RAW = ($rawHits -join ', ') } else { $RAW = 'no signatures' }

# ---------------- risk / value judgement ----------------
# HIGH = encryption is live and currently UNLOCKED -> keys live in RAM right now.
$risk = 'NONE'
if ($fdeHits.Count -gt 0 -or $rawHits.Count -gt 0) { $risk = 'MED' }
if ($blActive -or $vcHits.Count -gt 0) { $risk = 'HIGH' }

try {
    $dir = Split-Path $OutCsv -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ($rows.Count -eq 0) { Add-Row 'None' '-' 'CLEAN' '' 'no disk encryption detected' }
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv -ErrorAction Stop
} catch {}

'BL|' + $BL
'VC|' + $VC
'FDE|' + $FDE
'RAW|' + $RAW
'RISK|' + $risk
'CSV|' + $OutCsv
