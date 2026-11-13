// Defender exclusions, via WMI instead of Add-MpPreference.
//
// The cmdlets live in a PowerShell module, so on the 2026-08-13 host they were unusable. The
// same operations exist as static methods on MSFT_MpPreference in root\Microsoft\Windows\Defender.
//
// HYGIENE RULE (from v3.0, keep it): we remove ONLY exclusions this collector created
// (DFIRTriage_* / DFIRCollector_* under %TEMP%) and only when the folder is already gone.
// A stale exclusion left by other software on a target machine is EVIDENCE - this same
// collector gathers exclusions precisely to prove tampering - so it must never be cleaned up.

using System;
using System.Collections.Generic;
using System.IO;
using System.Management;

static class Defender
{
    const string NS = @"root\Microsoft\Windows\Defender";

    public static List<string> Current()
    {
        List<string> l = new List<string>();
        try
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                NS, "SELECT ExclusionPath FROM MSFT_MpPreference"))
                foreach (ManagementObject m in s.Get())
                {
                    string[] arr = m["ExclusionPath"] as string[];
                    if (arr != null) l.AddRange(arr);
                }
        }
        catch { }
        return l;
    }

    public static bool Add(string path)
    {
        return Invoke("Add", path);
    }

    public static bool Remove(string path)
    {
        return Invoke("Remove", path);
    }

    static bool Invoke(string method, string path)
    {
        try
        {
            using (ManagementClass cls = new ManagementClass(new ManagementScope(NS),
                       new ManagementPath("MSFT_MpPreference"), null))
            {
                ManagementBaseObject inp = cls.GetMethodParameters(method);
                inp["ExclusionPath"] = new string[] { path };
                cls.InvokeMethod(method, inp, null);
                return true;
            }
        }
        catch { return false; }
    }

    /// <summary>Drop our own leftovers from aborted earlier runs. Never touches foreign ones.</summary>
    public static int PurgeOwnStale()
    {
        int n = 0;
        string temp = Path.GetTempPath().TrimEnd('\\');
        foreach (string p in Current())
        {
            try
            {
                string q = p.TrimEnd('\\');
                string parent = Path.GetDirectoryName(q);
                string leaf = Path.GetFileName(q);
                if (parent == null || !string.Equals(parent.TrimEnd('\\'), temp, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!(leaf.StartsWith("DFIRTriage_", StringComparison.OrdinalIgnoreCase)
                   || leaf.StartsWith("DFIRCollector_", StringComparison.OrdinalIgnoreCase)))
                    continue;
                if (Directory.Exists(q)) continue;      // still in use by another run
                if (Remove(p)) n++;
            }
            catch { }
        }
        return n;
    }

    /// <summary>
    /// Snapshot the exclusion list AS EVIDENCE. Replaces the PowerShell_Defender_Exclusions
    /// KAPE module, which invoked powershell.exe and therefore died on a locked-down host.
    /// </summary>
    public static void WriteEvidence(string csvPath)
    {
        System.Text.StringBuilder sb = new System.Text.StringBuilder();
        sb.AppendLine("kind,value,exists");
        try
        {
            foreach (string p in Current())
                sb.AppendLine("ExclusionPath," + Env.Csv(p) + "," +
                              (Directory.Exists(p) || File.Exists(p) ? "yes" : "no"));
            foreach (string k in new string[] { "ExclusionProcess", "ExclusionExtension" })
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                    NS, "SELECT " + k + " FROM MSFT_MpPreference"))
                    foreach (ManagementObject m in s.Get())
                    {
                        string[] arr = m[k] as string[];
                        if (arr == null) continue;
                        foreach (string v in arr) sb.AppendLine(k + "," + Env.Csv(v) + ",");
                    }
            }
        }
        catch { }
        try { File.WriteAllText(csvPath, sb.ToString(), new System.Text.UTF8Encoding(false)); } catch { }
    }
}
