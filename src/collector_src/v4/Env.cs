// Self-diagnostics of the machine we are about to collect from.
//
// Two jobs, and the second one is the important one:
//   1. tell the collector which execution paths are usable, so it degrades openly
//      instead of dying halfway with an unreadable PowerShell error (2026-08-13 incident);
//   2. record the restrictions AS EVIDENCE. An administrator who says "I never disabled the
//      command prompt" on a machine where it IS disabled has just described an intrusion.
//      That belongs in the case file, not only on screen.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

class AvProduct
{
    public string Name;
    public bool Enabled;
    public bool IsDefender;
    public string Raw;
}

class Env
{
    public bool IsAdmin;
    public string CmdState = "?";        // OK | BLOCKED | ERROR
    public string CmdDetail = "";
    public string PsFileState = "?";     // OK | BLOCKED | MISSING
    public string PsStdinState = "?";    // OK | BLOCKED | MISSING
    public string PsLangMode = "?";      // FullLanguage | ConstrainedLanguage | ...
    public string PsPolicySource = "";   // where a policy-scoped ExecutionPolicy came from
    public List<AvProduct> Av = new List<AvProduct>();
    public string OsName = "?";
    public long RamBytes;

    public bool PsUsable { get { return PsStdinState == "OK" || PsFileState == "OK"; } }
    public bool ThirdPartyAv
    {
        get
        {
            foreach (AvProduct a in Av) if (!a.IsDefender && a.Enabled) return true;
            return false;
        }
    }

    const string TOKEN = "DFIRPROBE7742";

    public void Probe()
    {
        try
        {
            WindowsPrincipal p = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            IsAdmin = p.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { IsAdmin = false; }

        ProbeCmd();
        ProbePowerShell();
        ProbeAv();
        ProbeOs();
    }

    // ---- cmd ---------------------------------------------------------------------
    void ProbeCmd()
    {
        object v = Reg(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\System", "DisableCMD");
        if (v == null)
            v = Reg(RegistryHive.LocalMachine, @"Software\Policies\Microsoft\Windows\System", "DisableCMD");
        string policy = v == null ? null : Convert.ToString(v);

        string outp;
        bool ran = TryRun("cmd.exe", "/c echo " + TOKEN, null, out outp, 8000);
        bool ok = ran && outp != null && outp.Contains(TOKEN);

        if (ok)
        {
            CmdState = "OK";
            CmdDetail = policy == null ? "" : "політика DisableCMD=" + policy + ", але сценарії ще працюють";
        }
        else
        {
            CmdState = "BLOCKED";
            CmdDetail = policy != null
                ? "заблоковано політикою (DisableCMD=" + policy + ")"
                : "не запускається (причина невідома)";
        }
    }

    // ---- PowerShell --------------------------------------------------------------
    void ProbePowerShell()
    {
        string ps = PsExe();
        if (ps == null) { PsFileState = "MISSING"; PsStdinState = "MISSING"; return; }

        // Where an ExecutionPolicy came from matters: a policy-scoped one (GPO) OVERRIDES the
        // -ExecutionPolicy parameter we pass, which is precisely why v3 died on the ransomware
        // host while every earlier machine was fine.
        object hklm = Reg(RegistryHive.LocalMachine, @"Software\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy");
        object hkcu = Reg(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy");
        if (hklm != null) PsPolicySource = "GPO комп'ютера: " + hklm;
        else if (hkcu != null) PsPolicySource = "GPO користувача: " + hkcu;

        // 1) can we run a .ps1 FILE? (what v3 did everywhere)
        string tmp = Path.Combine(Path.GetTempPath(), "dfp_" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".ps1");
        try
        {
            File.WriteAllText(tmp, "Write-Output '" + TOKEN + "'\r\n", new UTF8Encoding(false));
            string o;
            bool ran = TryRun(ps, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + tmp + "\"",
                              null, out o, 25000);
            PsFileState = (ran && o != null && o.Contains(TOKEN)) ? "OK" : "BLOCKED";
        }
        catch { PsFileState = "BLOCKED"; }
        finally { try { File.Delete(tmp); } catch { } }

        // 2) can we feed the same code through stdin? ExecutionPolicy governs script FILES,
        //    not command text - verified on a host with the policy set to Restricted, where
        //    -File failed and this succeeded. This is the fallback that keeps the analytic
        //    steps alive on a locked-down machine until they are all ported to C#.
        try
        {
            string o;
            bool ran = TryRun(ps, "-NoProfile -NonInteractive -Command -",
                              "Write-Output '" + TOKEN + "'\r\n" +
                              "Write-Output ('LANG|' + $ExecutionContext.SessionState.LanguageMode)\r\n",
                              out o, 25000);
            PsStdinState = (ran && o != null && o.Contains(TOKEN)) ? "OK" : "BLOCKED";
            if (o != null)
            {
                int i = o.IndexOf("LANG|", StringComparison.Ordinal);
                if (i >= 0)
                {
                    string rest = o.Substring(i + 5);
                    int e = rest.IndexOfAny(new char[] { '\r', '\n' });
                    PsLangMode = (e < 0 ? rest : rest.Substring(0, e)).Trim();
                }
            }
        }
        catch { PsStdinState = "BLOCKED"; }
    }

    public static string PsExe()
    {
        string p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                                @"WindowsPowerShell\v1.0\powershell.exe");
        if (File.Exists(p)) return p;
        p = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows",
                         @"System32\WindowsPowerShell\v1.0\powershell.exe");
        return File.Exists(p) ? p : null;
    }

    // ---- antivirus ---------------------------------------------------------------
    void ProbeAv()
    {
        try
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                @"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct"))
            {
                foreach (ManagementObject mo in s.Get())
                {
                    AvProduct a = new AvProduct();
                    a.Name = Convert.ToString(mo["displayName"]);
                    int st = 0;
                    try { st = Convert.ToInt32(mo["productState"]); } catch { }
                    a.Raw = "0x" + st.ToString("X6");
                    a.Enabled = (st & 0x1000) != 0;   // documented bit for "real-time on"
                    a.IsDefender = a.Name != null &&
                        a.Name.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) >= 0;
                    Av.Add(a);
                }
            }
        }
        catch { }
    }

    void ProbeOs()
    {
        try
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                "SELECT Caption, TotalVisibleMemorySize FROM Win32_OperatingSystem"))
            {
                foreach (ManagementObject mo in s.Get())
                {
                    OsName = Convert.ToString(mo["Caption"]);
                    try { RamBytes = Convert.ToInt64(mo["TotalVisibleMemorySize"]) * 1024L; } catch { }
                    break;
                }
            }
        }
        catch { }
        if (RamBytes == 0)
        {
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                    "SELECT TotalPhysicalMemory FROM Win32_ComputerSystem"))
                    foreach (ManagementObject mo in s.Get())
                    { RamBytes = Convert.ToInt64(mo["TotalPhysicalMemory"]); break; }
            }
            catch { }
        }
    }

    // ---- rendering ---------------------------------------------------------------
    public void Render()
    {
        Ui.Section("[ 0 ]  СЕРЕДОВИЩЕ   (машина, на якій ЗАПУЩЕНО збирач)");

        Ui.Field("Права", IsAdmin ? "Адміністратор" : "БЕЗ прав адміністратора",
                 IsAdmin ? Ui.Sev.Good : Ui.Sev.Bad);

        Ui.Field("cmd.exe",
                 CmdState == "OK" ? "працює" : "ЗАБЛОКОВАНО - " + CmdDetail,
                 CmdState == "OK" ? Ui.Sev.Good : Ui.Sev.Bad);

        string psTxt;
        Ui.Sev psSev;
        if (PsFileState == "MISSING") { psTxt = "не знайдено"; psSev = Ui.Sev.Bad; }
        else if (PsFileState == "OK") { psTxt = "працює"; psSev = Ui.Sev.Good; }
        else if (PsStdinState == "OK")
        {
            psTxt = "сценарії ЗАБЛОКОВАНО" + (PsPolicySource == "" ? "" : " (" + PsPolicySource + ")")
                  + " - працюю в обхід";
            psSev = Ui.Sev.Warn;
        }
        else { psTxt = "ЗАБЛОКОВАНО повністю"; psSev = Ui.Sev.Bad; }
        Ui.Field("PowerShell", psTxt, psSev);

        if (PsLangMode != "?" && PsLangMode != "FullLanguage")
            Ui.Field("Режим мови", PsLangMode + " (обмежений)", Ui.Sev.Warn);

        if (Av.Count == 0)
            Ui.Field("Антивірус", "не визначено", Ui.Sev.Unknown);
        else
        {
            List<string> names = new List<string>();
            foreach (AvProduct a in Av) names.Add(a.Name + (a.Enabled ? " (активний)" : " (вимкнений)"));
            Ui.Field("Антивірус", string.Join(", ", names.ToArray()),
                     ThirdPartyAv ? Ui.Sev.Warn : Ui.Sev.Plain);
        }

        Ui.Field("Система", OsName + (RamBytes > 0 ? ",  RAM " + Ui.Gb(RamBytes) + " ГБ" : ""), Ui.Sev.Plain);

        bool restricted = CmdState != "OK" || PsFileState != "OK";
        if (restricted || ThirdPartyAv) Console.WriteLine("   " + new string('-', 60));

        if (restricted)
        {
            Ui.Line("      [!] На цій машині обмежено запуск програм.", Ui.Sev.Warn);
            Ui.Note("          Якщо адміністратор цього не робив - це ознака втручання.");
            Ui.Note("          Зафіксую у справі: environment_restrictions.csv");
            if (PsUsable || CmdState == "OK")
                Ui.Line("      [i] Збір триває у повному обсязі: обхідний шлях працює.", Ui.Sev.Good);
            else
                Ui.Line("      [!] Частина перевірок буде пропущена - це буде вказано у справі.", Ui.Sev.Bad);
        }
        if (ThirdPartyAv)
        {
            Ui.Line("      [!] Сторонній антивірус може блокувати інструменти збору.", Ui.Sev.Warn);
            Ui.Note("          Додайте теку збирача у винятки або призупиніть захист на час роботи.");
        }
    }

    /// <summary>The restrictions as a case artefact. Registered in INTEGRATION_CONTRACT.md.</summary>
    public void WriteCsv(string path)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("check,status,detail");
        Add(sb, "admin", IsAdmin ? "ok" : "no_admin", "");
        Add(sb, "cmd_exe", CmdState.ToLowerInvariant(), CmdDetail);
        Add(sb, "powershell_script_file", PsFileState.ToLowerInvariant(), PsPolicySource);
        Add(sb, "powershell_stdin", PsStdinState.ToLowerInvariant(), "");
        Add(sb, "powershell_language_mode", PsLangMode, "");
        foreach (AvProduct a in Av)
            Add(sb, "antivirus", a.Enabled ? "enabled" : "disabled", a.Name + " " + a.Raw);
        Add(sb, "os", "info", OsName);
        try { File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false)); } catch { }
    }

    static void Add(StringBuilder sb, string k, string st, string d)
    {
        sb.AppendLine(Csv(k) + "," + Csv(st) + "," + Csv(d));
    }

    public static string Csv(string s)
    {
        if (s == null) return "";
        if (s.IndexOfAny(new char[] { ',', '"', '\r', '\n' }) < 0) return s;
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    // ---- helpers -----------------------------------------------------------------
    static object Reg(RegistryHive hive, string sub, string name)
    {
        try
        {
            using (RegistryKey b = RegistryKey.OpenBaseKey(hive, RegistryView.Default))
            using (RegistryKey k = b.OpenSubKey(sub))
                return k == null ? null : k.GetValue(name);
        }
        catch { return null; }
    }

    /// <summary>
    /// Run a program, optionally feeding stdin, and capture stdout+stderr together.
    /// Returns false on timeout or launch failure. Never throws - a probe that throws would
    /// take down the start screen.
    /// </summary>
    public static bool TryRun(string exe, string args, string stdin, out string output, int timeoutMs)
    {
        output = null;
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.RedirectStandardInput = stdin != null;
            StringBuilder sb = new StringBuilder();
            using (Process p = new Process())
            {
                p.StartInfo = psi;
                p.OutputDataReceived += delegate (object s, DataReceivedEventArgs e)
                { if (e.Data != null) lock (sb) sb.AppendLine(e.Data); };
                p.ErrorDataReceived += delegate (object s, DataReceivedEventArgs e)
                { if (e.Data != null) lock (sb) sb.AppendLine(e.Data); };
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                if (stdin != null)
                {
                    p.StandardInput.Write(stdin);
                    p.StandardInput.Close();
                }
                if (!p.WaitForExit(timeoutMs))
                {
                    try { p.Kill(); } catch { }
                    lock (sb) output = sb.ToString();
                    return false;
                }
                p.WaitForExit();
            }
            lock (sb) output = sb.ToString();
            return true;
        }
        catch { return false; }
    }
}
