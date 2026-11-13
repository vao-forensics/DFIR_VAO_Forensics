$e = Join-Path $env:TEMP ('e' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $e | Out-Null
foreach ($d in (Get-ChildItem 'C:\DFIR_Triage' -Directory -ErrorAction SilentlyContinue)) {
    & robocopy $e $d.FullName /MIR /NJH /NJS /NFL /NDL /NC /NS /NP | Out-Null
    Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath $e -Recurse -Force -ErrorAction SilentlyContinue
'triage items left: ' + (Get-ChildItem 'C:\DFIR_Triage' -ErrorAction SilentlyContinue | Measure-Object).Count
