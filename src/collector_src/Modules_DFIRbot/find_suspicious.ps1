# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : find_suspicious.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : MFT-based suspicious file triage (READ-ONLY)
#  operator  : launched by a forensic examiner during evidence collection
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================
param(
    [string]$CsvDir  = "",
    [string]$OutFile = "",
    [int]$PerCategory = 500,
    [string]$OutCsv = ""
)
# Build suspicious_files.txt from the same MFTECmd $MFT CSV the tree uses.
# Grouped by WHY a file is suspicious, with full paths - so the examiner reads intent,
# not a flat dump. Several checks are free because MFTECmd already computes the column
# (SI<FN, uSecZeros, HasAds, ZoneIdContents).
#
# PERFORMANCE: ~800k MFT rows. Parse + classify happen inside compiled C# (Add-Type);
# a PowerShell row loop over 350 MB of CSV takes minutes. See build_fs_tree.ps1.
# ASCII-ONLY (code and output): console is CP1251, PS 5.1 breaks on non-ASCII literals.
# stdout: TOTAL|n  CAT|<name>=<count> (repeated)  TRUNC|0|1  OUT|<path>

if (-not $CsvDir)  { $CsvDir  = $PSScriptRoot }
if (-not $OutFile) { $OutFile = Join-Path $CsvDir 'suspicious_files.txt' }

$csv = $null
try {
    $csv = Get-ChildItem $CsvDir -Recurse -File -Filter '*.csv' -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -match 'MFTECmd' -and $_.Name -notmatch '\$J|Journal' } |
           Sort-Object Length -Descending | Select-Object -First 1
} catch {}
if (-not $csv) { 'TOTAL|0'; 'TRUNC|0'; 'OUT|'; exit 0 }

$src = @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

public class Suspects
{
    public static int Total, Trunc;
    public static List<string> Counts = new List<string>();

    class Hit { public string Path; public long Size; public string Extra; }

    static List<string> SplitCsv(string line)
    {
        var o = new List<string>(); var sb = new StringBuilder(); bool q = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (q) { if (c == '"') { if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; } else q = false; } else sb.Append(c); }
            else { if (c == '"') q = true; else if (c == ',') { o.Add(sb.ToString()); sb.Length = 0; } else sb.Append(c); }
        }
        o.Add(sb.ToString());
        return o;
    }

    static string Size(long b)
    {
        if (b >= 1073741824L) return (b / 1073741824.0).ToString("0.0", CultureInfo.InvariantCulture) + "G";
        if (b >= 1048576L) return (b / 1048576.0).ToString("0.0", CultureInfo.InvariantCulture) + "M";
        if (b >= 1024L) return (b / 1024.0).ToString("0", CultureInfo.InvariantCulture) + "K";
        return b + "B";
    }

    static readonly string[] ExeExt = { "exe", "dll", "sys", "scr", "com", "pif", "cpl", "jar", "msi", "ocx" };
    // Only these are worth reporting as "deleted executable" - deleted DLLs are produced by
    // every Windows update and drowned the list (1997 hits on a clean host).
    static readonly string[] DropExt = { "exe", "scr", "com", "pif" };
    // Strong: almost never legitimate inside a user profile.
    static readonly string[] ScriptExt = { "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "jse", "wsf", "wsh", "hta" };
    // Weak: .js/.py/.reg are everywhere in legitimate software and in a developer's own files
    // (5758 hits on this host). Reported ONLY when they sit in an attacker-favoured folder.
    static readonly string[] WeakScriptExt = { "js", "py", "reg" };
    static readonly string[] DocExt = { "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif" };
    static readonly string[] SysNames = { "svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
                                          "winlogon.exe", "explorer.exe", "smss.exe", "wininit.exe",
                                          "spoolsv.exe", "taskhostw.exe", "rundll32.exe" };

    // Folders where an executable has no business being.
    static readonly string[] NoExecPath = { "\\users\\public\\", "\\$recycle.bin\\", "\\windows\\temp\\",
                                            "\\perflogs\\", "\\appdata\\local\\temp\\", "\\downloads\\",
                                            "\\appdata\\roaming\\", "\\programdata\\", "\\temp\\", "\\tmp\\" };

    // Attacker-favoured folders. A weak signal only counts when it lands in one of these.
    static readonly string[] HotPath = { "\\users\\public\\", "\\$recycle.bin\\", "\\windows\\temp\\",
                                         "\\perflogs\\", "\\appdata\\local\\temp\\", "\\downloads\\",
                                         "\\temp\\", "\\tmp\\", "rar$",
                                         "\\start menu\\programs\\startup\\" };

    // Legitimate software genuinely lives in these - excluded to keep the list readable.
    // Every entry below was added because it produced real noise on a clean host.
    static readonly string[] Benign = { "\\windows\\winsxs\\", "\\windows\\servicing\\",
        "\\windows\\softwaredistribution\\", "\\windows\\installer\\", "\\windows\\system32\\",
        "\\windows\\syswow64\\", "\\windows\\assembly\\", "\\program files\\", "\\program files (x86)\\",
        "\\windows\\microsoft.net\\", "\\dfir\\", "\\dfir_triage\\", "\\windowsapps\\",
        "\\packages\\", "\\node_modules\\", "\\site-packages\\", "\\.lmstudio\\", "\\anaconda3\\",
        "\\python3", "\\nvidia corporation\\", "\\microsoft\\edgeupdate\\", "\\google\\update",
        // Windows Installer's own cache - 2947 legit runtime installers came from here
        "\\programdata\\package cache\\",
        // Defender platform + definition updates: hundreds of legit signed DLLs
        "\\windows defender\\", "\\microsoft\\installer\\", "\\package cache",
        // MFT entries whose parent record is gone: very common, no signal on its own
        "\\pathunknown\\",
        // PyInstaller extraction dirs - our OWN collector creates these
        "\\_mei", "\\dfir_tmp\\" };

    static bool In(string hay, string[] arr) { foreach (var a in arr) if (hay.Contains(a)) return true; return false; }
    static bool Is(string ext, string[] arr) { foreach (var a in arr) if (ext == a) return true; return false; }

    public static string Run(string csvPath, string outPath, int perCat, string csvOut)
    {
        var cat = new Dictionary<string, List<Hit>>();
        Action<string, string, long, string> add = (k, p, s, x) =>
        {
            List<Hit> l;
            if (!cat.TryGetValue(k, out l)) { l = new List<Hit>(); cat[k] = l; }
            l.Add(new Hit { Path = p, Size = s, Extra = x });
            Total++;
        };

        using (var sr = new StreamReader(csvPath))
        {
            string header = sr.ReadLine();
            if (header == null) return "";
            var c = SplitCsv(header);
            int iParent = c.IndexOf("ParentPath"), iName = c.IndexOf("FileName"),
                iExt = c.IndexOf("Extension"), iDir = c.IndexOf("IsDirectory"),
                iSize = c.IndexOf("FileSize"), iInUse = c.IndexOf("InUse"),
                iSiFn = c.IndexOf("SI<FN"), iUsec = c.IndexOf("uSecZeros"),
                iAds = c.IndexOf("HasAds"), iIsAds = c.IndexOf("IsAds"),
                iZone = c.IndexOf("ZoneIdContents");
            if (iParent < 0 || iName < 0) return "";

            string line;
            while ((line = sr.ReadLine()) != null)
            {
                if (line.Length == 0) continue;
                var f = SplitCsv(line);
                if (f.Count <= iName) continue;
                if (iDir >= 0 && f.Count > iDir && f[iDir] == "True") continue;

                string parent = f[iParent];
                string name = f[iName];
                if (name.Length == 0) continue;
                if (parent.Length > 0 && parent[0] == '.') parent = parent.Substring(1);
                string full = (parent.EndsWith("\\") ? parent : parent + "\\") + name;
                string lowFull = full.ToLowerInvariant();
                string lowName = name.ToLowerInvariant();
                string ext = (iExt >= 0 && f.Count > iExt) ? f[iExt].TrimStart('.').ToLowerInvariant() : "";
                long size = 0;
                if (iSize >= 0 && f.Count > iSize) long.TryParse(f[iSize], out size);
                bool deleted = iInUse >= 0 && f.Count > iInUse && f[iInUse] == "False";
                bool benign = In(lowFull, Benign);

                // 1. executables where they do not belong.
                // Split by confidence instead of dropping anything: a RUNNABLE dropped into a
                // classic staging folder is a real lead, while loose DLLs next to a portable
                // app (or in AppData/ProgramData vendor dirs) are everyday noise - they go to
                // the REVIEW bucket so recall stays 100% but the top of the file is actionable.
                if (Is(ext, ExeExt) && !benign && In(lowFull, NoExecPath))
                {
                    bool runnable = Is(ext, DropExt) || ext == "msi" || ext == "jar";
                    bool strictSpot = In(lowFull, HotPath);
                    if (runnable && strictSpot)
                        add("EXECUTABLE DROPPED IN A STAGING FOLDER", full, size, deleted ? "DELETED" : "");
                    else
                        add("EXECUTABLE IN AN UNUSUAL FOLDER (REVIEW)", full, size, deleted ? "DELETED" : "");
                }

                bool hot = In(lowFull, HotPath);

                // 2. scripts in user-writable places. Strong extensions count anywhere in a
                // profile; weak ones (.js/.py/.reg) only in an attacker-favoured folder.
                if (!benign &&
                    ((Is(ext, ScriptExt) && (lowFull.Contains("\\users\\") || In(lowFull, NoExecPath)))
                     || (Is(ext, WeakScriptExt) && hot)))
                    add("SCRIPT IN A USER-WRITABLE FOLDER", full, size, deleted ? "DELETED" : "");

                // 3. run straight out of an archiver temp folder (the classic phishing chain).
                // Test the PARENT FOLDER, not the whole path: matching "\\7z" anywhere caught
                // 7z.exe itself and every file under "\\Program Files\\7-Zip\\".
                string lowParent = parent.ToLowerInvariant();
                // 7-Zip extracts to %TEMP%\7zXXXXXXX - anchor on that, otherwise folders simply
                // NAMED 7za / 7zx64 (our own toolkit) match. WinRAR uses Temp\Rar$EXnn.nnn.
                bool inArchTmp = lowParent.Contains("rar$")
                              || lowParent.Contains("\\temp\\7z")
                              || lowParent.Contains("\\temp\\{");
                if ((Is(ext, ExeExt) || Is(ext, ScriptExt) || Is(ext, WeakScriptExt))
                    && inArchTmp && !benign)
                    add("EXECUTED FROM AN ARCHIVE TEMP FOLDER", full, size, deleted ? "DELETED" : "");

                // 4. double extension masquerade: "invoice.pdf.exe".
                // Requires EXACTLY two dots. .NET assemblies are dotted namespaces
                // (Microsoft.Ceres.DocParsing.FormatHandlers.Docx.dll) and were flagged
                // wholesale by a looser rule.
                if (Is(ext, ExeExt) && !benign)
                {
                    string stem = lowName;
                    int dots = 0;
                    foreach (var ch2 in stem) if (ch2 == '.') dots++;
                    if (dots == 2)
                    {
                        int d = stem.LastIndexOf('.');
                        string inner = stem.Substring(0, d);
                        int d2 = inner.LastIndexOf('.');
                        if (d2 > 0 && Is(inner.Substring(d2 + 1), DocExt))
                            add("DOUBLE EXTENSION (MASQUERADE)", full, size, "");
                    }
                }

                // 5. right-to-left override in the name - reverses how the name displays
                // (U+202E RLO, U+202B RLE). Escapes, not literals: this file must stay ASCII.
                if (name.IndexOf('\u202E') >= 0 || name.IndexOf('\u202B') >= 0)
                    add("RIGHT-TO-LEFT OVERRIDE IN NAME", full, size, "");

                // 6. system binary name outside the system folders
                if (Is(lowName, SysNames) && !lowFull.Contains("\\windows\\system32\\") &&
                    !lowFull.Contains("\\windows\\syswow64\\") && !lowFull.Contains("\\windows\\winsxs\\") &&
                    !lowFull.Contains("\\servicing\\") && !lowFull.Contains("\\windows\\softwaredistribution\\"))
                    add("SYSTEM BINARY NAME IN THE WRONG FOLDER", full, size, deleted ? "DELETED" : "");

                // 7. deleted executables - attacker cleanup. Runnables only: deleted DLLs are
                // ordinary Windows-update debris and produced 1997 hits on a clean host.
                if (deleted && Is(ext, DropExt) && !benign)
                    add("DELETED EXECUTABLE", full, size, "");

                // 8. timestomping indicators (MFTECmd computes both).
                // $SI older than $FN is a strong signal and stays broad; zeroed sub-second
                // precision is WEAK (5139 hits here - archive extraction and file copies cause
                // it too), so it only counts in an attacker-favoured folder.
                if (!benign && iSiFn >= 0 && f.Count > iSiFn && f[iSiFn] == "True" &&
                    (Is(ext, ExeExt) || Is(ext, ScriptExt)))
                    add("TIMESTOMP: $SI OLDER THAN $FN", full, size, "");
                // Zeroed sub-second precision alone is NOT evidence (archive extraction and
                // plain file copies zero it too). Report it only when a SECOND signal agrees -
                // that is how an examiner would actually use it.
                bool siFn = iSiFn >= 0 && f.Count > iSiFn && f[iSiFn] == "True";
                bool archTmp = inArchTmp;
                if (!benign && hot && iUsec >= 0 && f.Count > iUsec && f[iUsec] == "True" &&
                    (Is(ext, ExeExt) || Is(ext, ScriptExt)) && (siFn || archTmp))
                    add("TIMESTOMP: ZEROED SUB-SECOND + A SECOND SIGNAL", full, size,
                        siFn ? "also $SI<$FN" : "from archive temp");

                // 9. alternate data streams
                if (iIsAds >= 0 && f.Count > iIsAds && f[iIsAds] == "True" &&
                    !lowName.EndsWith(":zone.identifier") && !benign)
                    add("ALTERNATE DATA STREAM", full, size, "");

                // 10. startup persistence
                if (lowFull.Contains("\\start menu\\programs\\startup\\") && !lowName.EndsWith(".ini"))
                    add("IN A STARTUP FOLDER", full, size, deleted ? "DELETED" : "");

                // 11. downloaded from the internet (MOTW recorded right in the MFT)
                if (iZone >= 0 && f.Count > iZone && f[iZone].Length > 0 &&
                    (Is(ext, ExeExt) || Is(ext, ScriptExt)))
                {
                    string z = f[iZone].Replace("\r", " ").Replace("\n", " ");
                    if (z.Length > 160) z = z.Substring(0, 160);
                    add("DOWNLOADED FROM THE INTERNET (MOTW)", full, size, z);
                }
            }
        }

        var order = new List<string>(cat.Keys);
        order.Sort();
        using (var sw = new StreamWriter(outPath, false, new UTF8Encoding(false)))
        {
            sw.WriteLine("SUSPICIOUS FILES   (source: $MFT via MFTECmd)");
            sw.WriteLine("Generated: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sw.WriteLine("Source CSV: " + Path.GetFileName(csvPath));
            sw.WriteLine();
            sw.WriteLine("This is a LEAD LIST, not a verdict: every entry still needs confirmation.");
            sw.WriteLine("Grouped by WHY the file stands out. DELETED entries come from the MFT and");
            sw.WriteLine("cannot be seen by a normal directory listing.");
            sw.WriteLine("suspicious_files.csv next to this file holds the SAME rows in spreadsheet form");
            sw.WriteLine("      (path, reason, size, timestamps) for the bot and for sorting/filtering.");
            sw.WriteLine(new string('=', 78));
            sw.WriteLine();
            sw.WriteLine("SUMMARY");
            foreach (var k in order) sw.WriteLine("  " + cat[k].Count.ToString().PadLeft(7) + "  " + k);
            sw.WriteLine("  " + Total.ToString().PadLeft(7) + "  TOTAL");
            sw.WriteLine();

            foreach (var k in order)
            {
                var l = cat[k];
                sw.WriteLine(new string('-', 78));
                sw.WriteLine("[" + k + "]  " + l.Count + " item(s)");
                sw.WriteLine(new string('-', 78));
                int n = 0;
                foreach (var h in l)
                {
                    if (n >= perCat) { sw.WriteLine("  ... " + (l.Count - perCat) + " more (per-category cap " + perCat + ")"); Trunc = 1; break; }
                    string extra = h.Extra.Length > 0 ? "   [" + h.Extra + "]" : "";
                    sw.WriteLine("  " + h.Path + "   (" + Size(h.Size) + ")" + extra);
                    n++;
                }
                sw.WriteLine();
            }
        }

        // Machine-readable twin of the TXT: the hashing step consumes this so we hash
        // exactly what was flagged, instead of re-deriving the target set.
        if (!string.IsNullOrEmpty(csvOut))
        {
            using (var cw = new StreamWriter(csvOut, false, new UTF8Encoding(false)))
            {
                cw.WriteLine("Category,Path,SizeBytes,Note");
                foreach (var k in order)
                    foreach (var h in cat[k])
                        cw.WriteLine("\"" + k.Replace("\"", "\"\"") + "\",\"" +
                                     h.Path.Replace("\"", "\"\"") + "\"," + h.Size + ",\"" +
                                     h.Extra.Replace("\"", "\"\"") + "\"");
            }
        }

        foreach (var k in order) Counts.Add(k + "=" + cat[k].Count);
        return outPath;
    }
}
'@

try { Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop } catch {
    'TOTAL|0'; 'TRUNC|1'; 'OUT|'; exit 0
}

$res = ''
if (-not $OutCsv) { $OutCsv = [System.IO.Path]::ChangeExtension($OutFile, '.csv') }
try { $res = [Suspects]::Run($csv.FullName, $OutFile, $PerCategory, $OutCsv) } catch { $res = '' }

'TOTAL|' + [Suspects]::Total
foreach ($c in [Suspects]::Counts) { 'CAT|' + $c }
'TRUNC|' + [Suspects]::Trunc
'OUT|' + $res
