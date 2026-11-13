# Build DFIR_VAO_Host_Agent.exe with the .NET Framework csc (C# 5), same toolchain as the collector builder.
#   powershell -ExecutionPolicy Bypass -File src\host_agent\make_agent.ps1 [-Out out]
param([string]$Out = 'out')
$ErrorActionPreference = 'Stop'
$me = $PSScriptRoot
New-Item -ItemType Directory -Force $Out | Out-Null
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$exe = Join-Path (Resolve-Path $Out).Path 'DFIR_VAO_Host_Agent.exe'
& $csc /nologo /target:winexe /optimize+ /codepage:65001 `
    /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll `
    /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll `
    "/out:$exe" "$me\HostAgent.cs" "$me\Serve.cs" "$me\AgentForm.cs"
if ($LASTEXITCODE -ne 0) { throw "csc failed ($LASTEXITCODE)" }
$h = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
"$h  DFIR_VAO_Host_Agent.exe" | Set-Content (Join-Path (Split-Path $exe) 'DFIR_VAO_Host_Agent.exe.sha256')
Write-Output ("built {0} ({1:N0} KB) sha256 {2}" -f $exe, ((Get-Item $exe).Length / 1KB), $h)
