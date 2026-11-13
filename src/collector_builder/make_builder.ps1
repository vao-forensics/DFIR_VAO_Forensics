# Build DFIR_Collector_Builder.exe from the repository: pack the collector sources, our KAPE
# definitions and the tool manifest as resources, then compile with the .NET Framework csc.
#
#   powershell -ExecutionPolicy Bypass -File src\collector_builder\make_builder.ps1 [-Repo .] [-Mirror URL] [-Out out]
#
# -Mirror: where {mirror} tools live (release "tools-mirror" of the repository). CI passes
#          https://github.com/<owner>/<repo>/releases/download/tools-mirror
param(
    [string]$Repo = (Resolve-Path "$PSScriptRoot\..\..").Path,
    [string]$Mirror = '',
    [string]$Out = 'out'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$src = Join-Path $Repo 'src\collector_src'
$me = Join-Path $Repo 'src\collector_builder'
$res = Join-Path $env:TEMP ('dfir_builder_res_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $res, $Out | Out-Null

function Stage-Zip($dir, $zip) {
    if (Test-Path $zip) { Remove-Item $zip }
    [IO.Compression.ZipFile]::CreateFromDirectory($dir, $zip, [IO.Compression.CompressionLevel]::Optimal, $false)
}

# core.zip: collector v4 sources (Seal_key.cs is written by the builder), VaoTriage.cs, manifest, icon
$core = Join-Path $res 'core'
New-Item -ItemType Directory -Force "$core\v4" | Out-Null
Get-ChildItem "$src\v4" -Filter *.cs | Where-Object Name -ne 'Seal_key.cs' | Copy-Item -Destination "$core\v4"
Copy-Item "$src\VaoTriage.cs", "$src\launcher.manifest", "$src\collector.ico" $core
Stage-Zip $core "$res\core.zip"

# defs.zip: KAPE Targets/Modules definitions + our modules as Modules\!DFIRbot + overlay files
$defs = Join-Path $res 'defs'
Copy-Item "$src\kape_defs" $defs -Recurse
New-Item -ItemType Directory -Force "$defs\Modules\!DFIRbot" | Out-Null
Copy-Item "$src\Modules_DFIRbot\*" "$defs\Modules\!DFIRbot" -Recurse
$bad = Get-Content "$defs\Modules\!DFIRbot\vao_collect_all.ps1" -Encoding Byte | Where-Object { $_ -gt 127 }
if ($bad) { throw "vao_collect_all.ps1 has non-ASCII bytes: PowerShell 5.1 would read it as ANSI" }
Stage-Zip $defs "$res\defs.zip"

Copy-Item "$src\tools.json" "$res\tools.json"
[IO.File]::WriteAllText("$res\mirror.txt", $Mirror)

$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$exe = Join-Path (Resolve-Path $Out).Path 'DFIR_Collector_Builder.exe'
& $csc /nologo /target:winexe /optimize+ /codepage:65001 `
    "/win32icon:$src\collector.ico" "/win32manifest:$me\builder.manifest" `
    /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll `
    /reference:System.Web.Extensions.dll /reference:System.Management.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll `
    "/resource:$res\core.zip,core.zip" "/resource:$res\defs.zip,defs.zip" `
    "/resource:$res\tools.json,tools.json" "/resource:$res\mirror.txt,mirror.txt" `
    "/out:$exe" "$me\Builder.cs" "$me\BuilderForm.cs"
if ($LASTEXITCODE -ne 0) { throw "csc failed ($LASTEXITCODE)" }
Remove-Item $res -Recurse -Force
$h = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
"$h  DFIR_Collector_Builder.exe" | Set-Content (Join-Path (Split-Path $exe) 'DFIR_Collector_Builder.exe.sha256')
Write-Output ("built {0} ({1:N0} KB) sha256 {2}" -f $exe, ((Get-Item $exe).Length / 1KB), $h)
