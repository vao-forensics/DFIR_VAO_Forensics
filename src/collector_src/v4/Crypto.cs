// Disk-encryption detection - the panel the operator reads BEFORE deciding anything.
//
// Port of Modules\!DFIRbot\check_encryption.ps1 to managed code, with one behavioural change
// that is the whole reason for the rewrite:
//
//   v3 printed "[OK] Шифрування не виявлено" when the CHECK ITSELF had failed to run.
//   On 2026-08-13 that message appeared on a machine encrypted by ransomware, because Group
//   Policy blocked the .ps1 and the .bat could not tell "clean" from "never ran".
//
// So every probe here returns three states, and NotRun is rendered as a warning, never as a
// clean result. Same detections as the original: BitLocker, VeraCrypt/TrueCrypt, virtual
// volumes with no backing partition, third-party FDE services, raw boot-sector signatures.

using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Text;

enum Probe { Clean, Detected, NotRun }

class EncResult
{
    public Probe BlState = Probe.NotRun, VcState = Probe.NotRun,
                 FdeState = Probe.NotRun, RawState = Probe.NotRun;
    public string Bl = "", Vc = "", Fde = "", Raw = "";
    public string BlWhy = "", VcWhy = "", FdeWhy = "", RawWhy = "";
    public bool BlActive, VcActive;
    public List<string[]> Rows = new List<string[]>();   // Type,Target,Status,Method,Details

    /// <summary>NONE / MED / HIGH, or UNKNOWN when nothing could be checked at all.</summary>
    public string Risk
    {
        get
        {
            if (BlActive || VcActive) return "HIGH";
            if (FdeState == Probe.Detected || RawState == Probe.Detected) return "MED";
            if (BlState == Probe.NotRun && VcState == Probe.NotRun
                && FdeState == Probe.NotRun && RawState == Probe.NotRun) return "UNKNOWN";
            return "NONE";
        }
    }

    public bool AnyNotRun
    {
        get
        {
            return BlState == Probe.NotRun || VcState == Probe.NotRun
                || FdeState == Probe.NotRun || RawState == Probe.NotRun;
        }
    }
}

static class Crypto
{
    static readonly string[] Methods = { "None", "AES128+Diffuser", "AES256+Diffuser", "AES128",
                                         "AES256", "HardwareEncryption", "XTS-AES128", "XTS-AES256" };
    static readonly string[] Conv = { "FullyDecrypted", "FullyEncrypted", "EncryptionInProgress",
                                      "DecryptionInProgress", "EncryptionPaused", "DecryptionPaused" };

    public static EncResult Detect()
    {
        EncResult r = new EncResult();
        BitLocker(r);
        VeraCrypt(r);
        ThirdPartyFde(r);
        BootSectors(r);
        return r;
    }

    // ---- BitLocker ---------------------------------------------------------------
    static void BitLocker(EncResult r)
    {
        List<string> parts = new List<string>();
        try
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                @"root\CIMV2\Security\MicrosoftVolumeEncryption",
                "SELECT DriveLetter, ProtectionStatus, EncryptionMethod, ConversionStatus FROM Win32_EncryptableVolume"))
            {
                bool any = false;
                foreach (ManagementObject v in s.Get())
                {
                    any = true;
                    string dl = Str(v["DriveLetter"]);
                    if (dl.Length == 0) dl = "(без літери)";
                    int prot = Int(v["ProtectionStatus"]);
                    string m = Pick(Methods, Int(v["EncryptionMethod"]));
                    int cs = Int(v["ConversionStatus"]);
                    string c = Pick(Conv, cs);
                    string st = "OFF";
                    if (prot == 1) { st = "ON"; r.BlActive = true; parts.Add(dl + " ON (" + m + ")"); }
                    else if (cs != 0) { st = "PARTIAL"; parts.Add(dl + " " + c); }
                    r.Rows.Add(new string[] { "BitLocker", dl, st, m, c });
                }
                // The namespace answering with zero volumes is itself an answer: no
                // encryptable volumes were reported. Treat as checked-and-clean.
                r.BlState = parts.Count > 0 ? Probe.Detected : Probe.Clean;
                if (!any) r.BlWhy = "простір імен відповів, але томів не повернув";
            }
        }
        catch (Exception ex)
        {
            r.BlState = Probe.NotRun;
            r.BlWhy = Short(ex);
            r.Rows.Add(new string[] { "BitLocker", "-", "NOT_CHECKED", "", r.BlWhy });
        }
        r.Bl = parts.Count > 0 ? string.Join(", ", parts.ToArray()) : "";
    }

    // ---- VeraCrypt / TrueCrypt / container mounts ---------------------------------
    static void VeraCrypt(EncResult r)
    {
        List<string> hits = new List<string>();
        bool checkedSomething = false;

        try
        {
            foreach (string n in new string[] { "VeraCrypt", "VeraCrypt-x64", "TrueCrypt", "VeraCryptExpander" })
            {
                System.Diagnostics.Process[] ps = System.Diagnostics.Process.GetProcessesByName(n);
                if (ps != null && ps.Length > 0)
                {
                    hits.Add("процес " + n);
                    r.Rows.Add(new string[] { "VeraCrypt", n, "RUNNING", "", "process is running" });
                }
            }
            checkedSomething = true;
        }
        catch (Exception ex) { r.VcWhy = Short(ex); }

        foreach (string n in new string[] { "veracrypt", "truecrypt" })
        {
            try
            {
                string drv = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows",
                                          @"System32\drivers\" + n + ".sys");
                if (File.Exists(drv))
                {
                    hits.Add("драйвер " + n + ".sys");
                    r.Rows.Add(new string[] { "VeraCrypt", n + ".sys", "PRESENT", "", drv });
                }
                checkedSomething = true;
            }
            catch { }
        }

        // A volume that owns a drive letter but has no backing partition is a container /
        // VHD / ImDisk mount - i.e. data that is unlocked RIGHT NOW.
        try
        {
            HashSet<string> backed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                "SELECT Antecedent, Dependent FROM Win32_LogicalDiskToPartition"))
                foreach (ManagementObject a in s.Get())
                {
                    string dep = Str(a["Dependent"]);   // ...DeviceID="C:"
                    string l = LetterFromRef(dep);
                    if (l != null) backed.Add(l);
                }

            using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                "SELECT DeviceID, DriveType FROM Win32_LogicalDisk WHERE DriveType=3 OR DriveType=6"))
                foreach (ManagementObject d in s.Get())
                {
                    string id = Str(d["DeviceID"]);
                    if (id.Length == 0) continue;
                    string l = id.TrimEnd(':');
                    if (!backed.Contains(l))
                    {
                        hits.Add("змонтовано " + l + ":");
                        r.Rows.Add(new string[] { "VirtualVolume", l + ":", "MOUNTED", "",
                            "volume with no backing partition (container/VHD/VeraCrypt)" });
                    }
                }
            checkedSomething = true;
        }
        catch (Exception ex) { if (r.VcWhy.Length == 0) r.VcWhy = Short(ex); }

        r.VcActive = hits.Count > 0;
        r.Vc = hits.Count > 0 ? string.Join(", ", hits.ToArray()) : "";
        r.VcState = hits.Count > 0 ? Probe.Detected : (checkedSomething ? Probe.Clean : Probe.NotRun);
    }

    // ---- third-party full-disk encryption ----------------------------------------
    static readonly string[][] FdeMap = {
        new string[] { "eefdc|esetfde|eset full disk",                 "ESET Full Disk Encryption" },
        new string[] { "sgn|safeguard|utimaco",                        "Sophos/Utimaco SafeGuard" },
        new string[] { "pgpdisk|pgpsdk|symefa|eedservice|symantec endpoint encryption",
                                                                       "Symantec/PGP Encryption" },
        new string[] { "mfeepesrv|mfeepehost|mcafee drive",            "McAfee/Trellix Drive Encryption" },
        new string[] { "cpdiskmanager|pointsec|check point full disk", "Check Point Full Disk Encryption" },
        new string[] { "dcrypt",                                       "DiskCryptor" },
        new string[] { "bestcrypt|bcfsfltr",                           "BestCrypt" },
        new string[] { "winmagic|securedoc",                           "WinMagic SecureDoc" },
    };

    static void ThirdPartyFde(EncResult r)
    {
        List<string> hits = new List<string>();
        try
        {
            List<string[]> svcs = new List<string[]>();
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, State FROM Win32_Service"))
                foreach (ManagementObject m in s.Get())
                    svcs.Add(new string[] { Str(m["Name"]), Str(m["DisplayName"]), Str(m["State"]) });

            foreach (string[] rule in FdeMap)
            {
                string[] alts = rule[0].Split('|');
                foreach (string[] sv in svcs)
                {
                    string name = (sv[0] ?? "").ToLowerInvariant();
                    string disp = (sv[1] ?? "").ToLowerInvariant();
                    bool hit = false;
                    foreach (string alt in alts)
                        if (name.Contains(alt) || disp.Contains(alt)) { hit = true; break; }
                    if (!hit) continue;
                    if (!hits.Contains(rule[1])) hits.Add(rule[1]);
                    r.Rows.Add(new string[] { "ThirdPartyFDE", rule[1], sv[2], "", sv[0] + " / " + sv[1] });
                }
            }
            r.FdeState = hits.Count > 0 ? Probe.Detected : Probe.Clean;
        }
        catch (Exception ex)
        {
            r.FdeState = Probe.NotRun;
            r.FdeWhy = Short(ex);
            r.Rows.Add(new string[] { "ThirdPartyFDE", "-", "NOT_CHECKED", "", r.FdeWhy });
        }
        r.Fde = hits.Count > 0 ? string.Join(", ", hits.ToArray()) : "";
    }

    // ---- raw boot sectors --------------------------------------------------------
    static void BootSectors(EncResult r)
    {
        List<string> hits = new List<string>();
        int read = 0, seen = 0;
        try
        {
            List<int> idx = new List<int>();
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                    "SELECT DeviceID FROM Win32_DiskDrive"))
                    foreach (ManagementObject d in s.Get())
                    {
                        string id = Str(d["DeviceID"]);          // \\.\PHYSICALDRIVE0
                        int p = id.LastIndexOf("PHYSICALDRIVE", StringComparison.OrdinalIgnoreCase);
                        int n;
                        if (p >= 0 && int.TryParse(id.Substring(p + 13), out n)) idx.Add(n);
                    }
            }
            catch { }
            if (idx.Count == 0) for (int i = 0; i < 8; i++) idx.Add(i);   // fall back to probing

            foreach (int i in idx)
            {
                seen++;
                byte[] buf = Native.ReadPhysicalSectors(i, 512);
                if (buf == null) continue;      // no rights / no such disk - NOT "clean"
                read++;
                string sig = null;
                if (Native.Contains(buf, "-FVE-FS-")) sig = "BitLocker (-FVE-FS-)";
                else if (Native.Contains(buf, "VeraCrypt")) sig = "завантажувач VeraCrypt";
                else if (Native.Contains(buf, "TrueCrypt")) sig = "завантажувач TrueCrypt";
                else if (Native.Contains(buf, "LUKS")) sig = "LUKS (Linux)";
                else if (Native.Contains(buf, "SafeBoot") || Native.Contains(buf, "Pointsec")
                      || Native.Contains(buf, "SecureDoc")) sig = "стороннє pre-boot FDE";
                if (sig != null)
                {
                    hits.Add("диск " + i + " : " + sig);
                    r.Rows.Add(new string[] { "BootSector", @"\\.\PHYSICALDRIVE" + i, "SIGNATURE", "", sig });
                }
            }
        }
        catch (Exception ex) { r.RawWhy = Short(ex); }

        r.Raw = hits.Count > 0 ? string.Join(", ", hits.ToArray()) : "";
        if (hits.Count > 0) r.RawState = Probe.Detected;
        else if (read > 0) r.RawState = Probe.Clean;
        else
        {
            r.RawState = Probe.NotRun;
            if (r.RawWhy.Length == 0)
                r.RawWhy = seen > 0 ? "жоден фізичний диск не вдалося прочитати (потрібні права)"
                                    : "не вдалося перелічити фізичні диски";
            r.Rows.Add(new string[] { "BootSector", "-", "NOT_CHECKED", "", r.RawWhy });
        }
    }

    // ---- output ------------------------------------------------------------------
    public static void WriteCsv(EncResult r, string path)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("Type,Target,Status,Method,Details");
        if (r.Rows.Count == 0)
            sb.AppendLine("None,-,CLEAN,,no disk encryption detected");
        foreach (string[] row in r.Rows)
            sb.AppendLine(Env.Csv(row[0]) + "," + Env.Csv(row[1]) + "," + Env.Csv(row[2]) + ","
                        + Env.Csv(row[3]) + "," + Env.Csv(row[4]));
        try
        {
            string d = Path.GetDirectoryName(path);
            if (d != null && !Directory.Exists(d)) Directory.CreateDirectory(d);
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
        }
        catch { }
    }

    // ---- helpers -----------------------------------------------------------------
    static string Str(object o) { return o == null ? "" : Convert.ToString(o); }
    static int Int(object o) { try { return Convert.ToInt32(o); } catch { return -1; } }
    static string Pick(string[] a, int i) { return (i >= 0 && i < a.Length) ? a[i] : "Unknown"; }
    static string Short(Exception ex)
    {
        string m = ex.Message ?? ex.GetType().Name;
        m = m.Replace("\r", " ").Replace("\n", " ").Trim();
        return m.Length > 90 ? m.Substring(0, 90) : m;
    }

    /// <summary>Pull C from a WMI reference like ...Win32_LogicalDisk.DeviceID="C:"</summary>
    static string LetterFromRef(string s)
    {
        if (s == null) return null;
        int i = s.IndexOf("DeviceID=\"", StringComparison.OrdinalIgnoreCase);
        if (i < 0) return null;
        int j = s.IndexOf('"', i + 10);
        if (j < 0) return null;
        string v = s.Substring(i + 10, j - i - 10).TrimEnd(':');
        return v.Length == 1 ? v : null;
    }
}
