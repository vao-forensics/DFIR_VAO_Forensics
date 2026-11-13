# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : run_progress.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : progress display
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
# run_progress.ps1 - run a tool with verbose output HIDDEN (to a log) and show a
# compact in-place progress line instead. ASCII-only CODE (PS 5.1 parses safely);
# Ukrainian labels arrive via ENV at runtime. Params via ENV to dodge quoting hell:
#   PROG_EXE, PROG_ARGS, PROG_LOG, PROG_LABEL, PROG_PHASE
$Exe      = $env:PROG_EXE
$WorkArgs = $env:PROG_ARGS
$Log      = $env:PROG_LOG
$Label    = if ($env:PROG_LABEL) { $env:PROG_LABEL } else { "Processing" }
$Phase    = $env:PROG_PHASE

$ErrorActionPreference = 'SilentlyContinue'
# DO NOT set [Console]::OutputEncoding here. That setter calls SetConsoleOutputCP and
# changes the code page of the WHOLE CONSOLE, which outlives this script: afterwards cmd
# reads the CP1251 bytes of the .bat as UTF-8, so every later Cyrillic label and echo is
# parsed and rendered as garbage. The console is already chcp 1251 and the label arrives
# as a Unicode environment variable, so leaving the encoding alone is correct.
"" | Out-File -FilePath $Log -Encoding utf8
$err = "$Log.err"

$p = Start-Process -FilePath $Exe -ArgumentList $WorkArgs `
      -RedirectStandardOutput $Log -RedirectStandardError $err `
      -PassThru -WindowStyle Hidden

$spin = @('|','/','-','\')
$i = 0
$t0 = Get-Date
$barW = 22

function Short([string]$s) {
  if (-not $s) { return "" }
  $s = $s.Trim() -replace '\s+',' '
  if ($s.Length -gt 44) { $s = $s.Substring(0,44) + "..." }
  return $s
}

while (-not $p.HasExited) {
  Start-Sleep -Milliseconds 350
  $last = ""
  try { $last = (Get-Content -LiteralPath $Log -Tail 1) } catch {}
  if (-not $last) { try { $last = (Get-Content -LiteralPath $err -Tail 1) } catch {} }
  $el = (Get-Date) - $t0
  $els = "{0:mm\:ss}" -f $el
  $pos = [int]($el.TotalSeconds) % $barW
  $bar = ("#" * $pos) + ("." * ($barW - $pos))
  $line = "  {0}  [{1}] {2}  {3}  [{4}]  {5}" -f $spin[$i % 4], $Phase, $Label, $els, $bar, (Short $last)
  if ($line.Length -gt 116) { $line = $line.Substring(0,116) }
  Write-Host ("`r" + $line.PadRight(116)) -NoNewline -ForegroundColor Green
  $i++
}
$el = (Get-Date) - $t0
$done = "  [OK] [{0}] {1} - done in {2:mm\:ss}" -f $Phase, $Label, $el
Write-Host ("`r" + $done.PadRight(116)) -ForegroundColor Green
exit $p.ExitCode
