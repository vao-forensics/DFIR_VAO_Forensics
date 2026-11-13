# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : resolve_drive.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : resolve drive letter
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
param([string]$In)
# Normalize a user-typed drive letter: uppercase + map Cyrillic homoglyphs (Ukrainian
# keyboard types -/-/- etc. that LOOK like Latin C/E/H) -> Latin, keep first A-Z letter.
$d = ($In + '').Trim().ToUpper()
$map = @{
    ([char]0x0421)='C'; ([char]0x0415)='E'; ([char]0x041D)='H'; ([char]0x0410)='A';
    ([char]0x0412)='B'; ([char]0x041A)='K'; ([char]0x041C)='M'; ([char]0x041E)='O';
    ([char]0x0420)='P'; ([char]0x0422)='T'; ([char]0x0425)='X'; ([char]0x0406)='I';
    ([char]0x0423)='Y'; ([char]0x0405)='S'; ([char]0x0408)='J'
}
$out = -join ($d.ToCharArray() | ForEach-Object { if ($map.ContainsKey($_)) { $map[$_] } else { $_ } })
$out = ($out -replace '[^A-Z]', '')
if ($out.Length -ge 1) { $out = $out.Substring(0, 1) }
Write-Output $out
