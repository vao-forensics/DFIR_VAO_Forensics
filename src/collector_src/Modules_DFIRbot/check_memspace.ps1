# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : check_memspace.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : free space check before a memory capture
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
param([string]$WorkRoot = "C:\DFIR_Triage")
# Estimate the disk space needed to collect pagefile.sys / swapfile.sys / hiberfil.sys
# and compare it with the free space on the work drive. Filling the victim's disk during
# a collection destroys evidence, so the bat disables memory-file collection on LOW.
# ASCII-ONLY on purpose: PS 5.1 reading a BOM-less file breaks on non-ASCII literals.
# Prints exactly one token: OK | LOW need=<n>GB free=<n>GB | UNKNOWN
try {
    $pf = (Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue |
           Measure-Object -Property AllocatedBaseSize -Sum).Sum
    if (-not $pf) { $pf = 0 }

    $ramMB = [math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory / 1MB)

    # hiberfil.sys only exists when hibernation is on; it is ~40% of RAM by default
    # (HiberFileSizePercent), so 45% is a safe over-estimate.
    $hib = 0
    $he = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' `
           -Name HibernateEnabled -ErrorAction SilentlyContinue).HibernateEnabled
    if ($he -eq 1) { $hib = [math]::Round($ramMB * 0.45) }

    # swapfile.sys is small (~256MB); +512MB margin, then 15% headroom for the zip step.
    $need = [math]::Round(($pf + $hib + 512) * 1.15)

    $drive = $WorkRoot.Substring(0, 1)
    $free = [math]::Round((Get-PSDrive $drive -ErrorAction Stop).Free / 1MB)

    if ($free -gt $need) {
        'OK'
    } else {
        'LOW need=' + [math]::Round($need / 1024) + 'GB free=' + [math]::Round($free / 1024) + 'GB'
    }
} catch {
    'UNKNOWN'
}
