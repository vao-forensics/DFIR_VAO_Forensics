// vao_triage.exe - one compiled binary replacing the PowerShell analysis scripts.
//
// WHY (measured on a real run, 2026-08-09): the collector generated 1706 PowerShell log
// events on the machine being examined - 1009 of them EventID 4100 (handled errors, e.g.
// Get-AuthenticodeSignature failing once per unsigned process), 342 EventID 4104 which
// writes OUR OWN SCRIPT TEXT into the victim's event log, and 265 engine-start events from
// 33 separate powershell.exe launches.
// In compiled code a handled failure is just a catch: it logs nothing at all. One process
// instead of 33. The examiner's timeline stops being polluted with our tooling.
//
// C# and not Python: csc.exe ships with Windows and we already compile the launcher with it,
// so nothing new travels to the target. A Python runtime would add ~50 MB, thousands more
// MFT records, and a python.exe on a workstation looks stranger than a single signed-looking
// utility.
//
// Commands (stdout stays KEY|value so the .bat parsing is unchanged):
//   execscan  --csvdir D --txt F --csv F
//   footprint --outdir D --selfdir D --workroot D --start ISO --version V

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

static class Vao
{
    // ------------------------------------------------------------------ tiny CSV reader --
    static List<string> SplitCsv(string line)
    {
        var outp = new List<string>();
        var sb = new StringBuilder();
        bool q = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (q)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else q = false;
                }
                else sb.Append(c);
            }
            else if (c == '"') q = true;
            else if (c == ',') { outp.Add(sb.ToString()); sb.Length = 0; }
            else sb.Append(c);
        }
        outp.Add(sb.ToString());
        return outp;
    }

    static List<Dictionary<string, string>> ReadCsv(string path)
    {
        var rows = new List<Dictionary<string, string>>();
        try
        {
            using (var sr = new StreamReader(path, Encoding.UTF8, true))
            {
                string header = sr.ReadLine();
                if (header == null) return rows;
                if (header.Length > 0 && header[0] == '\ufeff') header = header.Substring(1);
                var cols = SplitCsv(header);
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (line.Length == 0) continue;
                    var v = SplitCsv(line);
                    var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < cols.Count; i++)
                        d[cols[i]] = i < v.Count ? v[i] : "";
                    rows.Add(d);
                }
            }
        }
        catch { }
        return rows;
    }

    static string CsvEsc(string s)
    {
        if (s == null) return "";
        if (s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) < 0) return s;
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    static IEnumerable<string> FindCsvs(string dir, string pattern)
    {
        string[] all;
        try { all = Directory.GetFiles(dir, "*.csv", SearchOption.AllDirectories); }
        catch { yield break; }
        var rx = new Regex(pattern, RegexOptions.IgnoreCase);
        foreach (var f in all)
            if (rx.IsMatch(Path.GetFileName(f))) yield return f;
    }

    // --------------------------------------------------------------------- shared rules --
    // Kept identical to the PowerShell version that was already tuned against a known-clean
    // host (0 HIGH findings) and the Course lab data (16/16 caught).
    static readonly string[] CORE_SYSBIN = {
        "svchost.exe","lsass.exe","csrss.exe","smss.exe","wininit.exe","winlogon.exe",
        "services.exe","spoolsv.exe","taskhostw.exe","conhost.exe","sihost.exe","ctfmon.exe",
        "dwm.exe","searchindexer.exe","wuauclt.exe","lsaiso.exe","werfault.exe",
        "fontdrvhost.exe","sppsvc.exe","dllhost.exe" };
    static readonly string[] TOOL_SYSBIN = {
        "cmd.exe","powershell.exe","net.exe","net1.exe","nltest.exe","whoami.exe",
        "schtasks.exe","wscript.exe","cscript.exe","mshta.exe","certutil.exe","bitsadmin.exe",
        "wmic.exe","reg.exe","regsvr32.exe","rundll32.exe","msiexec.exe","explorer.exe",
        "at.exe","psexec.exe" };
    static readonly string[] SYSDIRS = { "system32", "syswow64", "winsxs", "sysnative" };
    static readonly string[] RECON = {
        "systeminfo.exe","tasklist.exe","ipconfig.exe","netstat.exe","net.exe","net1.exe",
        "quser.exe","whoami.exe","where.exe","nltest.exe","arp.exe","route.exe","nbtstat.exe",
        "hostname.exe","query.exe","dsquery.exe","netsh.exe" };

    static readonly Regex TRUSTED = new Regex(
        @"^[a-z]:\\(program files( \(x86\))?|windows\\(system32|syswow64|winsxs|servicing|softwaredistribution|microsoft\.net|assembly|windowsapps|immersivecontrolpanel|systemapps)|programdata\\package cache)\\",
        RegexOptions.IgnoreCase);
    static readonly Regex INSTALLER = new Regex(
        @"\\7zs[0-9a-f]{4,}\\|\\\{[0-9a-f-]{36}\}\\\.(ba|be|cr)\\|\\is-[a-z0-9]{6}\.tmp\\|\\_is[0-9]+\\|\\temp\\[0-9a-f{}-]{32,38}\\(dismhost|mpsigstub|mprecovery|wimserv)\.exe$|\\temp\\(mpsigstub|mprecovery|dismhost)\.exe$",
        RegexOptions.IgnoreCase);
    static readonly Regex SELF = new Regex(
        @"\\modules\\bin\\|\\dfir_triage\\|\\dfirtriage_|\\dfircollector_|\\kape\\|\\kape\.exe$|\\(mftecmd|pecmd|amcacheparser|appcompatcacheparser|evtxecmd|recmd|sbecmd|srumecmd|sqlecmd|jlecmd|lecmd|rbcmd|bstrings|hayabusa|chainsaw|thor-lite|browserparser|hindsight|bitsparser|dhparser|mplog_parser|leveldbdumper|vao_triage)\.exe$",
        RegexOptions.IgnoreCase);
    static readonly Regex EXEC = new Regex(
        @"\.(exe|scr|com|pif|bat|cmd|ps1|vbs|js|jse|wsf|dll|sys)$", RegexOptions.IgnoreCase);
    static readonly Regex DOUBLE_EXT = new Regex(
        @"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|txt|rtf|zip|rar)\.(exe|scr|com|pif|bat|cmd|js|vbs)$",
        RegexOptions.IgnoreCase);

    static readonly KeyValuePair<string, Regex>[] STAGING = {
        new KeyValuePair<string, Regex>("root_odd",   new Regex(@"^[a-z]:\\(intel|web|recovery|perflogs|temp)\\", RegexOptions.IgnoreCase)),
        new KeyValuePair<string, Regex>("recycle",    new Regex(@"\\\$recycle\.bin\\|\\recycler\\", RegexOptions.IgnoreCase)),
        new KeyValuePair<string, Regex>("sysvolinfo", new Regex(@"\\system volume information\\", RegexOptions.IgnoreCase)),
        new KeyValuePair<string, Regex>("public",     new Regex(@"\\users\\public\\", RegexOptions.IgnoreCase)),
        new KeyValuePair<string, Regex>("winsub",     new Regex(@"^[a-z]:\\windows\\(debug|help|media|ime|addins|repair|security|fonts|tasks|tracing|update)\\", RegexOptions.IgnoreCase)),
        new KeyValuePair<string, Regex>("profile",    new Regex(@"\\users\\[^\\]+\\(downloads|documents|desktop|music|pictures|videos)\\", RegexOptions.IgnoreCase)),
        new KeyValuePair<string, Regex>("appdata",    new Regex(@"\\appdata\\(local|roaming)\\[^\\]+$", RegexOptions.IgnoreCase)),
        new KeyValuePair<string, Regex>("temp",       new Regex(@"\\temp\\", RegexOptions.IgnoreCase)),
        new KeyValuePair<string, Regex>("sysprofile", new Regex(@"\\config\\systemprofile\\", RegexOptions.IgnoreCase)),
    };
    static readonly Dictionary<string, string> LEVEN_OK = new Dictionary<string, string> {
        {"ftp.exe","tftp.exe"},{"sc.exe","scw.exe"},{"tracert.exe","tracerpt.exe"},
        {"dxdiag.exe","dcdiag.exe"},{"taskhost.exe","taskhostw.exe"},{"fsutil.exe","dfsutil.exe"},
        {"net.exe","net1.exe"},{"chkdsk.exe","chkntfs.exe"},{"cmd.exe","cmdl32.exe"} };

    static string StagingOf(string low)
    {
        foreach (var kv in STAGING) if (kv.Value.IsMatch(low)) return kv.Key;
        return "";
    }
    static bool HasSeg(string low, string[] segs)
    {
        var parts = low.Split('\\');
        foreach (var s in segs) if (Array.IndexOf(parts, s) >= 0) return true;
        return false;
    }

    // Damerau-Levenshtein: plain Levenshtein PLUS adjacent transposition as ONE edit.
    // Without the transposition case the textbook scvhost.exe / svchost.exe pair scores 2 and
    // the single most famous typosquat in this class is missed. Found by the recall test.
    static int Lev(string a, string b)
    {
        int n = a.Length, m = b.Length;
        if (n == 0) return m;
        if (m == 0) return n;
        if (Math.Abs(n - m) > 2) return 9;
        var d = new int[n + 1, m + 1];
        for (int i = 0; i <= n; i++) d[i, 0] = i;
        for (int j = 0; j <= m; j++) d[0, j] = j;
        for (int i = 1; i <= n; i++)
            for (int j = 1; j <= m; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                int min = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                    min = Math.Min(min, d[i - 2, j - 2] + 1);
                d[i, j] = min;
            }
        return d[n, m];
    }

    class Rec { public string Path, Low, Name, When, Kind, Art, Sha1; }
    class Find
    {
        public string Rule, Sev, Name, Path, When, Kind, Art, Detail, Sha1;
    }

    static List<Find> F = new List<Find>();
    static void Add(string rule, string sev, string name, string path, string when,
                    string kind, string art, string detail, string sha1)
    {
        F.Add(new Find { Rule = rule, Sev = sev, Name = name, Path = path, When = when,
                         Kind = kind, Art = art, Detail = detail, Sha1 = sha1 });
    }

    // ------------------------------------------------------------------------ execscan --
    static int ExecScan(string csvDir, string txtOut, string csvOut)
    {
        var rows = new List<Rec>();
        var shim = new List<Rec>();

        foreach (var f in FindCsvs(csvDir, "AppCompatCache"))
            foreach (var r in ReadCsv(f))
            {
                string p; r.TryGetValue("Path", out p);
                if (string.IsNullOrEmpty(p)) continue;
                string w; r.TryGetValue("LastModifiedTimeUTC", out w);
                var o = new Rec { Path = p, Low = p.Replace('/', '\\').ToLowerInvariant(),
                                  Name = p.Split('\\').Last(), When = w ?? "",
                                  Kind = "file_mtime(shimcache)", Art = "ShimCache", Sha1 = "" };
                rows.Add(o); shim.Add(o);
            }
        foreach (var f in FindCsvs(csvDir, @"Amcache.*(Unassociated|Associated)FileEntries"))
            foreach (var r in ReadCsv(f))
            {
                string p; r.TryGetValue("FullPath", out p);
                if (string.IsNullOrEmpty(p)) continue;
                string w, n, s;
                r.TryGetValue("FileKeyLastWriteTimestamp", out w);
                r.TryGetValue("Name", out n);
                r.TryGetValue("SHA1", out s);
                rows.Add(new Rec { Path = p, Low = p.Replace('/', '\\').ToLowerInvariant(),
                                   Name = n ?? p.Split('\\').Last(), When = w ?? "",
                                   Kind = "first_seen(amcache)", Art = "Amcache", Sha1 = s ?? "" });
            }
        var pe = new List<Tuple<string, string, string>>();   // name, lastrun, runcount
        foreach (var f in FindCsvs(csvDir, @"PECmd_Output\.csv$"))
            foreach (var r in ReadCsv(f))
            {
                string n; r.TryGetValue("ExecutableName", out n);
                if (string.IsNullOrEmpty(n)) continue;
                string l, c;
                r.TryGetValue("LastRun", out l);
                r.TryGetValue("RunCount", out c);
                pe.Add(Tuple.Create(n.ToLowerInvariant(), l ?? "", c ?? ""));
            }

        // R1 / R1b - system binaries in the wrong place
        foreach (var o in rows)
        {
            string n = o.Name.ToLowerInvariant();
            if (Array.IndexOf(CORE_SYSBIN, n) < 0) continue;
            if (SELF.IsMatch(o.Low) || HasSeg(o.Low, SYSDIRS)) continue;
            Add("sysbin_wrong_place", "HIGH", o.Name, o.Path, o.When, o.Kind, o.Art,
                "tier-1 Windows system binary outside System32/SysWOW64", o.Sha1);
        }
        foreach (var o in rows)
        {
            string n = o.Name.ToLowerInvariant();
            if (Array.IndexOf(TOOL_SYSBIN, n) < 0) continue;
            if (SELF.IsMatch(o.Low) || HasSeg(o.Low, SYSDIRS) || INSTALLER.IsMatch(o.Low)) continue;
            string st = StagingOf(o.Low);
            if (st.Length == 0) continue;
            Add("sysbin_in_staging", "HIGH", o.Name, o.Path, o.When, o.Kind, o.Art,
                "Windows tool copied into a staging folder (" + st + ")", o.Sha1);
        }

        // R2 - executable running from a staging folder
        foreach (var o in rows)
        {
            if (SELF.IsMatch(o.Low) || TRUSTED.IsMatch(o.Low) || INSTALLER.IsMatch(o.Low)) continue;
            if (!EXEC.IsMatch(o.Low)) continue;
            string st = StagingOf(o.Low);
            if (st.Length == 0) continue;
            string sev = "MEDIUM";
            if (st == "profile") sev = "LOW";
            else if (st == "recycle" || st == "sysvolinfo" || st == "winsub" || st == "sysprofile") sev = "HIGH";
            Add("staging_" + st, sev, o.Name, o.Path, o.When, o.Kind, o.Art,
                "executable in staging folder: " + st, o.Sha1);
        }

        // R3 - straight out of WinRAR's temp folder
        var rar = new Regex(@"\\rar\$[a-z0-9]+", RegexOptions.IgnoreCase);
        foreach (var o in rows)
            if (rar.IsMatch(o.Low) && EXEC.IsMatch(o.Low))
                Add("archiver_temp", "HIGH", o.Name, o.Path, o.When, o.Kind, o.Art,
                    "executed from WinRAR temp - opened directly from an archive/attachment", o.Sha1);

        // R4 - UNC / admin share. Must not match the local device form \\?\ .
        var hosts = new SortedSet<string>();
        var unc = new Regex(@"^\\\\[^\\?]", RegexOptions.IgnoreCase);
        var adminShare = new Regex(@"^\\\\[^\\]+\\([a-z]\$|admin\$)\\", RegexOptions.IgnoreCase);
        foreach (var o in rows)
        {
            if (!unc.IsMatch(o.Low)) continue;
            var parts = o.Low.Split('\\');
            if (parts.Length < 3 || parts[2].Length == 0) continue;
            string sev = "MEDIUM", why = "executable referenced over a network share";
            if (adminShare.IsMatch(o.Low))
            { sev = "HIGH"; why = "ADMIN SHARE (c$/admin$) - classic lateral movement"; }
            hosts.Add(parts[2]);
            Add("unc_admin_share", sev, o.Name, o.Path, o.When, o.Kind, o.Art, why, o.Sha1);
        }

        // R5 - look-alike name
        var all = CORE_SYSBIN.Concat(TOOL_SYSBIN).ToArray();
        var seen = new HashSet<string>();
        foreach (var o in rows)
        {
            string n = o.Name.ToLowerInvariant();
            if (!n.EndsWith(".exe") || Array.IndexOf(all, n) >= 0) continue;
            if (SELF.IsMatch(o.Low) || TRUSTED.IsMatch(o.Low) || INSTALLER.IsMatch(o.Low)) continue;
            if (n.Length - 4 < 5) continue;
            string key = n + "|" + o.Low;
            if (!seen.Add(key)) continue;
            foreach (var s in all)
            {
                if (s.Length - 4 < 5) continue;
                if (Lev(n, s) != 1) continue;
                string v;
                if ((LEVEN_OK.TryGetValue(s, out v) && v == n) ||
                    (LEVEN_OK.TryGetValue(n, out v) && v == s)) continue;
                Add("lookalike_name", "HIGH", o.Name, o.Path, o.When, o.Kind, o.Art,
                    "one character away from the real " + s, o.Sha1);
                break;
            }
        }

        // R6 - double extension
        foreach (var o in rows)
        {
            if (SELF.IsMatch(o.Low)) continue;
            if (DOUBLE_EXT.IsMatch(o.Low))
                Add("double_extension", "HIGH", o.Name, o.Path, o.When, o.Kind, o.Art,
                    "double extension - pretends to be a document", o.Sha1);
        }

        // R7 - rename pattern, only where nothing should be installed at all
        var byKey = new Dictionary<string, List<Rec>>();
        foreach (var o in shim)
        {
            if (o.When.Length == 0) continue;
            if (SELF.IsMatch(o.Low) || TRUSTED.IsMatch(o.Low) || INSTALLER.IsMatch(o.Low)) continue;
            string st = StagingOf(o.Low);
            if (st != "recycle" && st != "sysvolinfo" && st != "winsub" &&
                st != "sysprofile" && st != "public" && st != "root_odd") continue;
            int i = o.Low.LastIndexOf('\\');
            string k = (i > 0 ? o.Low.Substring(0, i) : o.Low) + "|" + o.When;
            List<Rec> l;
            if (!byKey.TryGetValue(k, out l)) { l = new List<Rec>(); byKey[k] = l; }
            l.Add(o);
        }
        foreach (var kv in byKey)
        {
            var names = kv.Value.Select(x => x.Name.ToLowerInvariant()).Distinct().OrderBy(x => x).ToArray();
            if (names.Length < 2) continue;
            Add("possible_rename", "MEDIUM", string.Join(" / ", names), kv.Value[0].Path,
                kv.Value[0].When, kv.Value[0].Kind, "ShimCache",
                "same folder and same file mtime under " + names.Length + " different names -" +
                " a rename leaves exactly this trace (not proof on its own)", "");
        }

        // R8 - mtime copied from a tier-1 system binary
        var stamps = new Dictionary<string, string>();
        foreach (var o in shim)
        {
            if (o.When.Length == 0 || !HasSeg(o.Low, SYSDIRS)) continue;
            if (Array.IndexOf(CORE_SYSBIN, o.Name.ToLowerInvariant()) < 0) continue;
            stamps[o.When] = o.Name;
        }
        foreach (var o in shim)
        {
            if (o.When.Length == 0 || HasSeg(o.Low, SYSDIRS)) continue;
            if (SELF.IsMatch(o.Low) || TRUSTED.IsMatch(o.Low) || INSTALLER.IsMatch(o.Low)) continue;
            if (StagingOf(o.Low).Length == 0) continue;
            string donor;
            if (stamps.TryGetValue(o.When, out donor))
                Add("timestamp_copied", "MEDIUM", o.Name, o.Path, o.When, o.Kind, "ShimCache",
                    "file mtime identical to the system binary " + donor, "");
        }

        // R9 - recon burst (real execution times, from Prefetch)
        var rec = new List<Tuple<string, DateTime>>();
        foreach (var p in pe)
        {
            if (Array.IndexOf(RECON, p.Item1) < 0) continue;
            DateTime t;
            if (!DateTime.TryParse(p.Item2, CultureInfo.InvariantCulture, DateTimeStyles.None, out t)) continue;
            rec.Add(Tuple.Create(p.Item1, t));
        }
        rec.Sort((x, y) => x.Item2.CompareTo(y.Item2));
        int a2 = 0;
        while (a2 < rec.Count)
        {
            int b2 = a2;
            var tools = new SortedSet<string>();
            while (b2 < rec.Count && (rec[b2].Item2 - rec[a2].Item2).TotalMinutes <= 15)
            { tools.Add(rec[b2].Item1); b2++; }
            if (tools.Count >= 4)
            {
                int span = (int)(rec[b2 - 1].Item2 - rec[a2].Item2).TotalMinutes;
                Add("recon_burst", "HIGH", string.Join(", ", tools), "",
                    rec[a2].Item2.ToString("yyyy-MM-dd HH:mm:ss"), "execution(prefetch)", "Prefetch",
                    tools.Count + " recon tools within " + span + " min", "");
                a2 = b2;
            }
            else a2++;
        }

        // R10 - inbound remote access
        foreach (var p in pe)
        {
            string why = null;
            if (p.Item1 == "wsmprovhost.exe") why = "INBOUND PowerShell Remoting was served on this host";
            else if (p.Item1 == "rdpclip.exe") why = "RDP session clipboard - an interactive RDP session took place";
            else if (p.Item1 == "psexesvc.exe") why = "PsExec service ran on this host";
            if (why != null)
                Add("remote_access", "HIGH", p.Item1, "", p.Item2, "execution(prefetch)", "Prefetch",
                    why + " (run count " + p.Item3 + ")", "");
        }

        WriteFindings(txtOut, csvOut, hosts);
        return 0;
    }

    static void WriteFindings(string txtOut, string csvOut, SortedSet<string> hosts)
    {
        var order = new Dictionary<string, int> { { "HIGH", 0 }, { "MEDIUM", 1 }, { "LOW", 2 } };
        var all = F.OrderBy(x => order.ContainsKey(x.Sev) ? order[x.Sev] : 3)
                   .ThenBy(x => x.Rule).ThenBy(x => x.Name).ToList();
        var byRule = all.GroupBy(x => x.Rule).OrderBy(g => g.Key).ToList();

        var L = new List<string>();
        L.Add("=================================================================");
        L.Add(" EXECUTION ARTEFACT FINDINGS  (ShimCache / Amcache / Prefetch)");
        L.Add(" generated by the DFIR collector - " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        L.Add("=================================================================");
        L.Add("");
        L.Add("HOW TO READ THE TIMESTAMPS - this is where most mistakes are made:");
        L.Add("  file_mtime(shimcache)  the FILE modification time. NOT an execution time.");
        L.Add("                         On Win7+ ShimCache holds no execution time at all,");
        L.Add("                         and an entry does not by itself prove execution.");
        L.Add("  first_seen(amcache)    when the Amcache entry was written (~first seen).");
        L.Add("  execution(prefetch)    a REAL execution time. Run counts are real too.");
        L.Add("");
        L.Add("NOTE: ShimCache is flushed to the SYSTEM hive only on reboot, so activity");
        L.Add("      since the last reboot may be missing from it.");
        L.Add("");
        L.Add("TOTAL FINDINGS: " + all.Count);
        foreach (var g in byRule) L.Add(string.Format("  {0,-24} {1}", g.Key, g.Count()));
        if (hosts.Count > 0)
        {
            L.Add("");
            L.Add("*** OTHER HOSTS REFERENCED (investigate these too) ***");
            foreach (var h in hosts) L.Add("    " + h);
        }
        foreach (var g in byRule)
        {
            L.Add("");
            L.Add("-----------------------------------------------------------------");
            L.Add(string.Format("[{0}]  {1} finding(s)", g.Key, g.Count()));
            L.Add("-----------------------------------------------------------------");
            int n = 0;
            foreach (var f in g)
            {
                if (n >= 200) { L.Add("    ... and " + (g.Count() - n) + " more (see the CSV)"); break; }
                L.Add(string.Format("  [{0}] {1}", f.Sev, f.Name));
                if (!string.IsNullOrEmpty(f.Path)) L.Add("        path : " + f.Path);
                if (!string.IsNullOrEmpty(f.When)) L.Add("        when : " + f.When + "   (" + f.Kind + ")");
                if (!string.IsNullOrEmpty(f.Sha1)) L.Add("        sha1 : " + f.Sha1);
                L.Add("        why  : " + f.Detail + "   [" + f.Art + "]");
                n++;
            }
        }
        if (all.Count == 0)
        {
            L.Add("");
            L.Add("No execution-artefact anomalies matched. This is a normal result on a");
            L.Add("clean machine and is NOT by itself proof that nothing happened.");
        }
        try { File.WriteAllLines(txtOut, L, Encoding.ASCII); } catch { }
        try
        {
            var c = new List<string> { "rule,severity,name,path,when,when_kind,artifact,detail,sha1" };
            foreach (var f in all)
                c.Add(string.Join(",", new[] { CsvEsc(f.Rule), CsvEsc(f.Sev), CsvEsc(f.Name),
                    CsvEsc(f.Path), CsvEsc(f.When), CsvEsc(f.Kind), CsvEsc(f.Art),
                    CsvEsc(f.Detail), CsvEsc(f.Sha1) }));
            File.WriteAllLines(csvOut, c, new UTF8Encoding(true));
        }
        catch { }

        Console.WriteLine("TOTAL|" + all.Count);
        foreach (var g in byRule) Console.WriteLine("RULE|" + g.Key + "=" + g.Count());
        Console.WriteLine("HOSTS|" + string.Join(",", hosts));
        Console.WriteLine("OUT|" + txtOut);
    }

    // ----------------------------------------------------------------------- footprint --
    static int Footprint(string outDir, string selfDir, string workRoot, string startIso, string version)
    {
        // The .bat passes its own %TS% (yyyyMMdd_HHmmss, used for the case folder name), so
        // parse that shape first and only then fall back to a general parse.
        DateTime t0;
        if (!DateTime.TryParseExact(startIso, "yyyyMMdd_HHmmss", CultureInfo.InvariantCulture,
                                    DateTimeStyles.None, out t0) &&
            !DateTime.TryParse(startIso, out t0))
            t0 = DateTime.Now.AddHours(-2);
        DateTime t1 = DateTime.Now;

        var lines = new List<string>();
        var csv = new List<string> { "kind,name,path,when,note" };
        Action<string, string, string, string, string> row = (k, n, p, w, note) =>
            csv.Add(string.Join(",", new[] { CsvEsc(k), CsvEsc(n), CsvEsc(p), CsvEsc(w), CsvEsc(note) }));

        string[] ourExes = new string[0];
        try
        {
            if (!string.IsNullOrEmpty(selfDir) && Directory.Exists(selfDir))
                ourExes = Directory.GetFiles(selfDir, "*.exe", SearchOption.AllDirectories);
        }
        catch { }
        foreach (var e in ourExes)
            row("our_binary", Path.GetFileName(e), e, "", "shipped by the collector - not attacker tooling");

        var pf = new List<FileInfo>();
        try
        {
            foreach (var p in Directory.GetFiles(@"C:\Windows\Prefetch", "*.pf"))
            {
                var fi = new FileInfo(p);
                if (fi.CreationTime >= t0 && fi.CreationTime <= t1.AddMinutes(5)) pf.Add(fi);
            }
        }
        catch { }
        foreach (var p in pf)
            row("prefetch_created", p.Name, p.FullName, p.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"),
                "created DURING this triage - execution evidence of OUR tool, not of the incident");

        int tempFiles = 0;
        try
        {
            if (!string.IsNullOrEmpty(selfDir) && Directory.Exists(selfDir))
                tempFiles = Directory.GetFiles(selfDir, "*", SearchOption.AllDirectories).Length;
        }
        catch { }
        row("temp_tree", "extracted_files", selfDir, t0.ToString("yyyy-MM-dd HH:mm:ss"),
            tempFiles + " files unpacked here and deleted afterwards; their $MFT records carry " +
            "TODAY as creation time and may survive as deleted entries");
        row("work_root", "output_folder", workRoot, t0.ToString("yyyy-MM-dd HH:mm:ss"),
            "where the archives were written by this triage");
        foreach (var p in new[] { workRoot, selfDir })
            if (!string.IsNullOrEmpty(p))
                row("defender_exclusion", "added_by_collector", p, "", "added at start, removed at end");

        lines.Add("=================================================================");
        lines.Add(" COLLECTOR FOOTPRINT - what THIS triage itself left on the machine");
        lines.Add("=================================================================");
        lines.Add("");
        lines.Add("READ THIS BEFORE BUILDING A TIMELINE FROM AN IMAGE OF THIS MACHINE.");
        lines.Add("");
        lines.Add("A live triage runs programs, so Windows records it: Prefetch, Amcache,");
        lines.Add("ShimCache, SRUM and the MFT all gain entries stamped with the time of");
        lines.Add("COLLECTION, not of the incident. If the disk is imaged later, these");
        lines.Add("entries appear in the timeline and can be mistaken for intruder activity.");
        lines.Add("Everything listed below is OURS. Subtract it.");
        lines.Add("");
        lines.Add("collector version : " + version);
        lines.Add("run started       : " + t0.ToString("yyyy-MM-dd HH:mm:ss"));
        lines.Add("run ended         : " + t1.ToString("yyyy-MM-dd HH:mm:ss"));
        lines.Add("machine           : " + Environment.MachineName);
        lines.Add("account           : " + Environment.UserName);
        lines.Add("temp folder       : " + selfDir);
        lines.Add("output folder     : " + workRoot);
        lines.Add("");
        lines.Add("SUMMARY");
        lines.Add("  executables shipped by us : " + ourExes.Length);
        lines.Add("  Prefetch entries created  : " + pf.Count);
        lines.Add("  files unpacked to temp    : " + tempFiles);
        lines.Add("");
        lines.Add("WHAT WE DID NOT CHANGE: no registry keys were written for the purpose of");
        lines.Add("collection, no services installed, no drivers loaded, no reboot. The only");
        lines.Add("deliberate system change is the pair of Defender exclusions listed below,");
        lines.Add("added before the tools ran and removed when the run finished.");
        lines.Add("");
        lines.Add("-----------------------------------------------------------------");
        lines.Add("[prefetch_created]  " + pf.Count + " entr(ies)");
        lines.Add("-----------------------------------------------------------------");
        foreach (var p in pf.OrderBy(x => x.CreationTime))
            lines.Add("  " + p.Name + "   " + p.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"));
        lines.Add("");
        lines.Add("-----------------------------------------------------------------");
        lines.Add("[our_binaries]  " + ourExes.Length + " file(s) - these names may appear in");
        lines.Add("Prefetch / Amcache / ShimCache with today's timestamp. They are ours.");
        lines.Add("-----------------------------------------------------------------");
        foreach (var e in ourExes.Select(Path.GetFileName).Distinct().OrderBy(x => x))
            lines.Add("  " + e);

        try { File.WriteAllLines(Path.Combine(outDir, "_collector_footprint.txt"), lines, Encoding.ASCII); } catch { }
        try { File.WriteAllLines(Path.Combine(outDir, "_collector_footprint.csv"), csv, new UTF8Encoding(true)); } catch { }

        Console.WriteLine("EXE|" + ourExes.Length);
        Console.WriteLine("PF|" + pf.Count);
        Console.WriteLine("TMP|" + tempFiles);
        Console.WriteLine("OUT|" + Path.Combine(outDir, "_collector_footprint.txt"));
        return 0;
    }

    // ---------------------------------------------------------------------- screenshot --
    // LIVE only, and deliberately so: on a mounted image there is no screen, and a picture of
    // the EXAMINER's desktop in the evidence would be worse than useless.
    // Value: what was actually open at the moment of seizure - ransom note, chat window,
    // wiper dialog, an open crypto wallet - none of which survives in any other artefact.
    static int Screenshot(string outDir)
    {
        int n = 0;
        try
        {
            var asmDraw = System.Reflection.Assembly.Load("System.Drawing, Version=4.0.0.0, " +
                "Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
            var asmForms = System.Reflection.Assembly.Load("System.Windows.Forms, Version=4.0.0.0, " +
                "Culture=neutral, PublicKeyToken=b77a5c561934e089");
            var screenT = asmForms.GetType("System.Windows.Forms.Screen");
            var all = (Array)screenT.GetProperty("AllScreens").GetValue(null, null);
            var bmpT = asmDraw.GetType("System.Drawing.Bitmap");
            var gfxT = asmDraw.GetType("System.Drawing.Graphics");
            var fmtT = asmDraw.GetType("System.Drawing.Imaging.ImageFormat");
            object png = fmtT.GetProperty("Png").GetValue(null, null);

            string dir = Path.Combine(outDir, "live");
            Directory.CreateDirectory(dir);
            foreach (var sc in all)
            {
                object bounds = screenT.GetProperty("Bounds").GetValue(sc, null);
                var bt = bounds.GetType();
                int x = (int)bt.GetProperty("X").GetValue(bounds, null);
                int y = (int)bt.GetProperty("Y").GetValue(bounds, null);
                int w = (int)bt.GetProperty("Width").GetValue(bounds, null);
                int h = (int)bt.GetProperty("Height").GetValue(bounds, null);
                if (w <= 0 || h <= 0) continue;
                object bmp = Activator.CreateInstance(bmpT, new object[] { w, h });
                object g = gfxT.GetMethod("FromImage").Invoke(null, new object[] { bmp });
                var sz = Activator.CreateInstance(asmDraw.GetType("System.Drawing.Size"),
                                                  new object[] { w, h });
                gfxT.GetMethod("CopyFromScreen", new[] { typeof(int), typeof(int), typeof(int),
                        typeof(int), sz.GetType() })
                    .Invoke(g, new object[] { x, y, 0, 0, sz });
                string f = Path.Combine(dir, "screenshot_" + (n + 1) + ".png");
                bmpT.GetMethod("Save", new[] { typeof(string), fmtT })
                    .Invoke(bmp, new object[] { f, png });
                ((IDisposable)g).Dispose();
                ((IDisposable)bmp).Dispose();
                n++;
            }
            var note = new List<string> {
                "Desktop screenshot(s) taken at the moment of collection.",
                "Time: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                "Machine: " + Environment.MachineName + "   Account: " + Environment.UserName,
                "",
                "This shows what was on screen when the triage ran - open windows, a ransom",
                "note, a chat, a mounted encrypted volume. None of that survives anywhere else.",
                "It is a picture of the CURRENT session, not of the incident."
            };
            File.WriteAllLines(Path.Combine(dir, "screenshot_README.txt"), note, Encoding.ASCII);
        }
        catch { }
        Console.WriteLine("SHOTS|" + n);
        return 0;
    }

    // ---------------------------------------------------------------------------- main --
    static string Arg(string[] a, string name, string def)
    {
        for (int i = 0; i < a.Length - 1; i++)
            if (string.Equals(a[i], "--" + name, StringComparison.OrdinalIgnoreCase)) return a[i + 1];
        return def;
    }

    static int Main(string[] args)
    {
        // long paths: same runtime switches as the collector (see Lp.cs there) - execscan
        // walks whatever KAPE copied, and a deep profile tree must not end it
        try
        {
            AppContext.SetSwitch("Switch.System.IO.UseLegacyPathHandling", false);
            AppContext.SetSwitch("Switch.System.IO.BlockLongPaths", false);
        }
        catch { }
        if (args.Length == 0) { Console.WriteLine("usage: vao_triage <execscan|footprint> [options]"); return 2; }
        try
        {
            switch (args[0].ToLowerInvariant())
            {
                case "execscan":
                    {
                        string dir = Arg(args, "csvdir", ".");
                        return ExecScan(dir,
                            Arg(args, "txt", Path.Combine(dir, "execution_findings.txt")),
                            Arg(args, "csv", Path.Combine(dir, "execution_findings.csv")));
                    }
                case "screenshot":
                    return Screenshot(Arg(args, "outdir", "."));
                case "footprint":
                    return Footprint(Arg(args, "outdir", "."), Arg(args, "selfdir", ""),
                                     Arg(args, "workroot", ""), Arg(args, "start", ""),
                                     Arg(args, "version", ""));
                default:
                    Console.WriteLine("unknown command: " + args[0]);
                    return 2;
            }
        }
        catch (Exception ex)
        {
            // Deliberately swallowed: a triage tool must never abort the collection, and an
            // uncaught .NET exception would also write a WER/Application-log entry on the
            // machine we are examining - more of exactly the noise this binary exists to avoid.
            Console.WriteLine("ERR|" + ex.Message);
            return 1;
        }
    }
}
