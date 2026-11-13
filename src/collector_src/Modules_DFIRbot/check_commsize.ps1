# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : check_commsize.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : estimate messenger data size before collection
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
param([int]$LargeGB = 20, [int]$HugeGB = 100)
# Pre-flight size probe for the mail+messenger opt-in.
# KAPE has NO file-size option and .tkape has no size filter, so the ONLY way to stop a comms
# collection from ballooning (a stock Telegram target once pulled 382 GB of VM images out of
# Downloads\Telegram Desktop) is to measure BEFORE collecting.
# IMPORTANT: for the Telegram downloads folder we now collect ONLY selected attachment types
# (see Targets\!DFIRbot\DFIRbot_Telegram.tkape), so the probe must measure the SAME masked
# subset - otherwise a huge folder of media would raise a false alarm.
# ASCII-ONLY: PS 5.1 reading a BOM-less file breaks on non-ASCII literals.
# stdout: TOTAL|<gb>  BIG|<gb> <path>  VERDICT|OK|LARGE|HUGE

# paths collected in full
$fullPaths = @(
    'AppData\Roaming\Telegram Desktop',
    'AppData\Roaming\Signal\attachments.noindex',
    'AppData\Roaming\WhatsApp',
    'AppData\Roaming\ViberPC',
    'AppData\Roaming\Skype',
    'AppData\Roaming\discord',
    'AppData\Local\Microsoft\Outlook',
    'Documents\Outlook Files',
    'AppData\Roaming\Thunderbird'
)
# path collected by extension mask only - must mirror DFIRbot_Telegram.tkape
$maskedPath = 'Downloads\Telegram Desktop'
$maskedExt = @('.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.pdf', '.rtf',
               '.exe', '.js', '.vbs', '.ps1', '.lnk', '.scr')

$total = 0.0
$bigSize = 0.0
$bigPath = 'none'

function Add-Size($gb, $path) {
    $script:total += $gb
    if ($gb -gt $script:bigSize) { $script:bigSize = $gb; $script:bigPath = $path }
}

try {
    $users = Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction Stop |
             Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
    foreach ($u in $users) {
        foreach ($rel in $fullPaths) {
            $p = Join-Path $u.FullName $rel
            if (-not (Test-Path $p)) { continue }
            try {
                $s = (Get-ChildItem $p -Recurse -Force -File -ErrorAction SilentlyContinue |
                      Measure-Object -Property Length -Sum).Sum
                if (-not $s) { $s = 0 }
                Add-Size ($s / 1GB) $p
            } catch {}
        }
        $mp = Join-Path $u.FullName $maskedPath
        if (Test-Path $mp) {
            try {
                $s = (Get-ChildItem $mp -Recurse -Force -File -ErrorAction SilentlyContinue |
                      Where-Object { $maskedExt -contains $_.Extension.ToLower() } |
                      Measure-Object -Property Length -Sum).Sum
                if (-not $s) { $s = 0 }
                Add-Size ($s / 1GB) ($mp + ' (attachments only)')
            } catch {}
        }
    }
} catch {}

$verdict = 'OK'
if ($total -ge $LargeGB) { $verdict = 'LARGE' }
if ($total -ge $HugeGB)  { $verdict = 'HUGE' }

'TOTAL|' + [math]::Round($total, 1)
'BIG|' + [math]::Round($bigSize, 1) + ' ' + $bigPath
'VERDICT|' + $verdict
