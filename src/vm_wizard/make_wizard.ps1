# Build DFIR_VAO_VM_Wizard.exe with the .NET Framework csc (C# 5), same toolchain as the Host Agent.
#   powershell -ExecutionPolicy Bypass -File src\vm_wizard\make_wizard.ps1 [-Out out] [-Bootstrap installer\guest\dfir-guest-bootstrap.sh]
# The guest bootstrap is embedded, so the EXE and the script it drops into the guest are one version.
param([string]$Out = 'out', [string]$Bootstrap = '')
$ErrorActionPreference = 'Stop'
$me = $PSScriptRoot
if (-not $Bootstrap) { $Bootstrap = Join-Path $me '..\..\installer\guest\dfir-guest-bootstrap.sh' }
if (-not (Test-Path $Bootstrap)) { $Bootstrap = Join-Path $me 'dfir-guest-bootstrap.sh' }
New-Item -ItemType Directory -Force $Out | Out-Null
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$exe = Join-Path (Resolve-Path $Out).Path 'DFIR_VAO_VM_Wizard.exe'
& $csc /nologo /target:winexe /optimize+ /codepage:65001 `
    /reference:Microsoft.CSharp.dll /reference:System.Core.dll /reference:System.Management.dll `
    /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll `
    "/resource:$Bootstrap,dfir-guest-bootstrap.sh" `
    "/out:$exe" "$me\VmWizard.cs" "$me\WizardMain.cs"
if ($LASTEXITCODE -ne 0) { throw "csc failed ($LASTEXITCODE)" }
$h = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
"$h  DFIR_VAO_VM_Wizard.exe" | Set-Content (Join-Path (Split-Path $exe) 'DFIR_VAO_VM_Wizard.exe.sha256')
Write-Output ("built {0} ({1:N0} KB) sha256 {2}" -f $exe, ((Get-Item $exe).Length / 1KB), $h)
