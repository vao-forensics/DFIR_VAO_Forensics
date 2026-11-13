/*
  DFIR YARA ruleset — local, offline. Covers tooling in the owner's cases plus common
  malware families (stealers, loaders, C2, miners, ransomware, keyloggers, LOLBin abuse).
  Bind-mounted into the sidecar — edit + `docker compose restart tools-sidecar` to reload.
  Signatures are string-based (fast, offline). Extend freely.
*/

// ─────────────────────────── Remote access / tunnel / RDP ───────────────────────────
rule RAT_RemoteAccess_Tools
{
    meta:
        description = "Remote-access / tunnel tools (RAT) commonly abused"
        severity = "high"
        mitre = "T1219"
    strings:
        $a1 = "AnyDesk" ascii wide nocase
        $a2 = "rustdesk" ascii wide nocase
        $a3 = "ngrok" ascii wide nocase
        $a4 = "TeamViewer" ascii wide nocase
        $a5 = "LiteManager" ascii wide nocase
        $a6 = "Remote Utilities" ascii wide nocase
        $a7 = "ScreenConnect" ascii wide nocase
        $a8 = "MeshAgent" ascii wide nocase
        $a9 = "rutserv" ascii wide nocase
        $a10 = "UltraViewer" ascii wide nocase
        $a11 = "Ammyy" ascii wide nocase
        $a12 = "Atera" ascii wide nocase
        $a13 = "Splashtop" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule RDP_Wrapper_Enabler
{
    meta:
        description = "RDP Wrapper / multi-session RDP enabler"
        severity = "high"
        mitre = "T1021.001"
    strings:
        $s1 = "rdpwrap" ascii wide nocase
        $s2 = "RDPWInst" ascii wide nocase
        $s3 = "termsrv.dll" ascii wide nocase
        $s4 = "rdpwrap.ini" ascii wide nocase
    condition:
        2 of them
}

rule Tunneling_Proxy_Tool
{
    meta:
        description = "Tunneling / reverse-proxy tools"
        severity = "high"
        mitre = "T1572"
    strings:
        $t1 = "frpc" ascii wide nocase
        $t2 = "cloudflared" ascii wide nocase
        $t3 = "chisel" ascii wide nocase
        $t4 = "localtonet" ascii wide nocase
        $t5 = "playit" ascii wide nocase
        $t6 = "reverse tunnel" ascii wide nocase
        $t7 = "gost" ascii wide nocase
        $t8 = "nps client" ascii wide nocase
    condition:
        any of them
}

// ─────────────────────────── Credential access ───────────────────────────
rule Credential_Dumping_Tool
{
    meta:
        description = "Credential dumping (mimikatz / lsass access)"
        severity = "critical"
        mitre = "T1003"
    strings:
        $m1 = "mimikatz" ascii wide nocase
        $m2 = "sekurlsa" ascii wide nocase
        $m3 = "logonpasswords" ascii wide nocase
        $m4 = "gentilkiwi" ascii wide nocase
        $m5 = "privilege::debug" ascii wide nocase
        $m6 = "lsadump" ascii wide nocase
        $m7 = "wdigest" ascii wide nocase
        $m8 = "!processprotect" ascii wide nocase
    condition:
        any of them
}

rule NirSoft_CredHarvest
{
    meta:
        description = "NirSoft credential/browser recovery tools (dual-use, often abused)"
        severity = "medium"
        mitre = "T1555"
    strings:
        $n1 = "WebBrowserPassView" ascii wide nocase
        $n2 = "Mail PassView" ascii wide nocase
        $n3 = "mailpv" ascii wide nocase
        $n4 = "netpass" ascii wide nocase
        $n5 = "PasswordFox" ascii wide nocase
        $n6 = "ChromePass" ascii wide nocase
        $n7 = "NirSoft" ascii wide nocase
    condition:
        2 of them
}

// ─────────────────────────── Infostealers ───────────────────────────
rule Infostealer_Generic
{
    meta:
        description = "Generic infostealer artefacts (browser DB + wallet + exfil)"
        severity = "critical"
        mitre = "T1555.003"
    strings:
        $b1 = "Login Data" ascii wide
        $b2 = "cookies.sqlite" ascii wide nocase
        $b3 = "\\\\Local State" ascii wide
        $w1 = "wallet.dat" ascii wide nocase
        $w2 = "\\\\Exodus\\\\" ascii wide nocase
        $w3 = "MetaMask" ascii wide nocase
        $t1 = "\\\\Telegram Desktop\\\\tdata" ascii wide nocase
        $d1 = "Discord\\\\Local Storage" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Stealer_Family_Names
{
    meta:
        description = "Known infostealer family markers (RedLine/Raccoon/Vidar/Lumma/etc.)"
        severity = "critical"
        mitre = "T1005"
    strings:
        $s1 = "RedLine" ascii wide nocase
        $s2 = "Raccoon" ascii wide nocase
        $s3 = "Vidar" ascii wide nocase
        $s4 = "LummaC2" ascii wide nocase
        $s5 = "Lumma" ascii wide nocase
        $s6 = "StealC" ascii wide nocase
        $s7 = "Rhadamanthys" ascii wide nocase
        $s8 = "Meduza" ascii wide nocase
        $s9 = "Aurora Stealer" ascii wide nocase
        $s10 = "Mars Stealer" ascii wide nocase
    condition:
        any of them
}

// ─────────────────────────── C2 frameworks / loaders ───────────────────────────
rule CobaltStrike_Beacon
{
    meta:
        description = "Cobalt Strike beacon markers"
        severity = "critical"
        mitre = "T1071"
    strings:
        $c1 = "ReflectiveLoader" ascii wide nocase
        $c2 = "%s (admin)" ascii
        $c3 = "beacon.dll" ascii wide nocase
        $c4 = "%s.4%08x%08x%08x%08x%08x" ascii
        $c5 = "IEX (New-Object Net.Webclient)" ascii wide nocase
        $c6 = "can_dll_load" ascii
    condition:
        2 of them
}

rule Loader_Downloader
{
    meta:
        description = "Loader / downloader behaviour markers"
        severity = "high"
        mitre = "T1105"
    strings:
        $u1 = "URLDownloadToFile" ascii wide
        $u2 = "WinHttpConnect" ascii wide
        $u3 = "InternetOpenUrl" ascii wide
        $u4 = "certutil -urlcache" ascii wide nocase
        $u5 = "bitsadmin /transfer" ascii wide nocase
        $u6 = "Invoke-WebRequest" ascii wide nocase
        $s1 = "\\\\Temp\\\\" ascii wide nocase
        $s2 = "CreateProcess" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of ($u*) and 1 of ($s*)
}

// ─────────────────────────── Execution / scripts ───────────────────────────
rule Suspicious_PowerShell_Cradle
{
    meta:
        description = "PowerShell download/exec cradle or encoded command"
        severity = "high"
        mitre = "T1059.001"
    strings:
        $p1 = "IEX" ascii wide nocase
        $p2 = "Invoke-Expression" ascii wide nocase
        $p3 = "DownloadString" ascii wide nocase
        $p4 = "DownloadFile" ascii wide nocase
        $p5 = "FromBase64String" ascii wide nocase
        $p6 = "-EncodedCommand" ascii wide nocase
        $p7 = "-enc " ascii wide nocase
        $p8 = "Net.WebClient" ascii wide nocase
        $p9 = "-nop -w hidden" ascii wide nocase
        $p10 = "Reflection.Assembly" ascii wide nocase
    condition:
        2 of them
}

rule Obfuscated_Script
{
    meta:
        description = "Heavily obfuscated script (char-code / concat / base64 blobs)"
        severity = "medium"
        mitre = "T1027"
    strings:
        $o1 = "[char]" ascii wide nocase
        $o2 = "-join" ascii wide nocase
        $o3 = "chr(" ascii wide nocase
        $o4 = "String.fromCharCode" ascii wide nocase
        $o5 = "eval(unescape" ascii wide nocase
        $o6 = "powershell -e " ascii wide nocase
    condition:
        2 of them
}

rule WebShell_Generic
{
    meta:
        description = "Generic webshell (PHP/ASPX/JSP)"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $w1 = "eval(" ascii nocase
        $w2 = "base64_decode(" ascii nocase
        $w3 = "system($_" ascii nocase
        $w4 = "shell_exec(" ascii nocase
        $w5 = "Request.Form[" ascii nocase
        $w6 = "Runtime.getRuntime().exec" ascii nocase
        $w7 = "cmd.exe /c" ascii wide nocase
        $w8 = "passthru(" ascii nocase
        $w9 = "assert($_" ascii nocase
    condition:
        2 of them
}

rule LOLBin_Abuse
{
    meta:
        description = "Living-off-the-land binary abuse patterns"
        severity = "medium"
        mitre = "T1218"
    strings:
        $l1 = "regsvr32 /s /u /i:" ascii wide nocase
        $l2 = "rundll32 javascript:" ascii wide nocase
        $l3 = "mshta http" ascii wide nocase
        $l4 = "wmic process call create" ascii wide nocase
        $l5 = "msiexec /q /i http" ascii wide nocase
        $l6 = "InstallUtil.exe" ascii wide nocase
    condition:
        any of them
}

// ─────────────────────────── Persistence / keylog / miner ───────────────────────────
rule Keylogger_Markers
{
    meta:
        description = "Keylogger API / behaviour markers"
        severity = "high"
        mitre = "T1056.001"
    strings:
        $k1 = "SetWindowsHookEx" ascii wide
        $k2 = "GetAsyncKeyState" ascii wide
        $k3 = "GetKeyboardState" ascii wide
        $k4 = "WH_KEYBOARD_LL" ascii wide
        $k5 = "[BACKSPACE]" ascii wide nocase
        $k6 = "[ENTER]" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule CryptoMiner
{
    meta:
        description = "Crypto-currency miner (XMRig / stratum)"
        severity = "high"
        mitre = "T1496"
    strings:
        $x1 = "xmrig" ascii wide nocase
        $x2 = "stratum+tcp" ascii wide nocase
        $x3 = "--donate-level" ascii wide nocase
        $x4 = "cryptonight" ascii wide nocase
        $x5 = "randomx" ascii wide nocase
        $x6 = "nicehash" ascii wide nocase
    condition:
        any of them
}

rule Persistence_Autorun
{
    meta:
        description = "Persistence via run keys / services / scheduled tasks (script markers)"
        severity = "medium"
        mitre = "T1547"
    strings:
        $r1 = "CurrentVersion\\\\Run" ascii wide nocase
        $r2 = "schtasks /create" ascii wide nocase
        $r3 = "sc create" ascii wide nocase
        $r4 = "New-Service" ascii wide nocase
        $r5 = "Register-ScheduledTask" ascii wide nocase
        $r6 = "\\\\Startup\\\\" ascii wide nocase
    condition:
        2 of them
}

// ─────────────────────────── Defense evasion / ransomware ───────────────────────────
rule Defender_Tamper
{
    meta:
        description = "Windows Defender / AV tampering"
        severity = "high"
        mitre = "T1562.001"
    strings:
        $d1 = "Set-MpPreference -DisableRealtimeMonitoring" ascii wide nocase
        $d2 = "Add-MpPreference -ExclusionPath" ascii wide nocase
        $d3 = "DisableAntiSpyware" ascii wide nocase
        $d4 = "sc stop WinDefend" ascii wide nocase
        $d5 = "net stop " ascii wide nocase
        $d6 = "wevtutil cl" ascii wide nocase
    condition:
        any of them
}

rule Ransomware_Note
{
    meta:
        description = "Ransomware note / encryption marker"
        severity = "critical"
        mitre = "T1486"
    strings:
        $r1 = "your files have been encrypted" ascii wide nocase
        $r2 = "decrypt" ascii wide nocase
        $r3 = "bitcoin" ascii wide nocase
        $r4 = "recover your files" ascii wide nocase
        $r5 = ".onion" ascii wide nocase
        $r6 = "how to decrypt" ascii wide nocase
        $r7 = "all your data" ascii wide nocase
        $r8 = "readme.txt" ascii wide nocase
    condition:
        2 of them
}

rule Ransomware_Family_Names
{
    meta:
        description = "Known ransomware family markers"
        severity = "critical"
        mitre = "T1486"
    strings:
        $f1 = "LockBit" ascii wide nocase
        $f2 = "BlackCat" ascii wide nocase
        $f3 = "ALPHV" ascii wide nocase
        $f4 = "Conti" ascii wide nocase
        $f5 = "Ryuk" ascii wide nocase
        $f6 = "Phobos" ascii wide nocase
        $f7 = "Medusa" ascii wide nocase
        $f8 = "Akira" ascii wide nocase
        $f9 = "vssadmin delete shadows" ascii wide nocase
    condition:
        any of them
}

rule ShadowCopy_Deletion
{
    meta:
        description = "Volume shadow copy / backup deletion (pre-ransomware)"
        severity = "high"
        mitre = "T1490"
    strings:
        $v1 = "vssadmin delete shadows" ascii wide nocase
        $v2 = "wmic shadowcopy delete" ascii wide nocase
        $v3 = "bcdedit /set" ascii wide nocase
        $v4 = "wbadmin delete catalog" ascii wide nocase
        $v5 = "Delete-VMSnapshot" ascii wide nocase
    condition:
        any of them
}

// ─────────────────────────── Recon / packers ───────────────────────────
rule Recon_Scanner_Tool
{
    meta:
        description = "Network recon / scanning tools"
        severity = "medium"
        mitre = "T1046"
    strings:
        $n1 = "Advanced IP Scanner" ascii wide nocase
        $n2 = "netscan" ascii wide nocase
        $n3 = "SoftPerfect" ascii wide nocase
        $n4 = "PsExec" ascii wide nocase
        $n5 = "nltest" ascii wide nocase
        $n6 = "AdFind" ascii wide nocase
        $n7 = "BloodHound" ascii wide nocase
        $n8 = "SharpHound" ascii wide nocase
    condition:
        any of them
}

rule Packed_Suspicious_PE
{
    meta:
        description = "Packed PE (UPX / common packer section names)"
        severity = "low"
        mitre = "T1027.002"
    strings:
        $u1 = "UPX0" ascii
        $u2 = "UPX1" ascii
        $u3 = ".themida" ascii
        $u4 = ".vmp0" ascii
        $u5 = ".aspack" ascii
        $u6 = "FSG!" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
