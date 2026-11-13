# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : vao_collect_all.ps1  (ALL PowerShell steps in ONE process)
#  collector : VAO DFIR Collector v4.0
#  purpose   : file tree, suspicious files, hashes, encrypted files, MOTW,
#              live response - all READ-ONLY collection
#  operator  : launched by a forensic examiner during evidence collection
#
#  This single file replaces six separate scripts on purpose: one PowerShell
#  process and one script-block record instead of six, so the machine under
#  examination is disturbed as little as possible.
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: VAO_DFIR_COLLECTOR_MARKER
# ==============================================================================

param(
    [string]$CsvDir = "",
    [string]$OutDir = "",
    [string]$Drive  = "C",
    [int]$Live      = 0
)

$ErrorActionPreference = 'Continue'

# ---------------- build_fs_tree.ps1 ----------------
function Invoke-VaoFsTree {
param(
    [string]$CsvDir  = "",
    [string]$OutFile = "",
    [int]$MaxDepth = 12,
    [int]$MaxLines = 200000
)
# Build a readable file/folder TREE from the MFTECmd $MFT CSV that !EZParser already produced.
# The MFT is the forensic source: it also carries DELETED entries, which a live directory walk
# can never show. Per-file detail stays in the CSV; this renders the DIRECTORY structure with
# per-folder file counts and sizes, which is small enough for a human to read.
# PERFORMANCE: a real volume is ~800k MFT records / ~350 MB of CSV. A PowerShell character
# loop over that takes many minutes, so the parse + aggregate + render all happen inside a
# compiled C# type (Add-Type) and run at .NET speed.
# ASCII-ONLY (code AND output): the console is CP1251 and PS 5.1 breaks on non-ASCII literals
# in a BOM-less file. Box drawing uses +-- and |.
# stdout: DIRS|n  FILES|n  DEL|n  TRUNC|0|1  OUT|<path>

if (-not $CsvDir)  { $CsvDir  = $PSScriptRoot }
if (-not $OutFile) { $OutFile = Join-Path $CsvDir 'filesystem_tree.txt' }

$csv = $null
try {
    $csv = Get-ChildItem $CsvDir -Recurse -File -Filter '*.csv' -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -match 'MFTECmd' -and $_.Name -notmatch '\$J|Journal' } |
           Sort-Object Length -Descending | Select-Object -First 1
} catch {}
if (-not $csv) { 'DIRS|0'; 'FILES|0'; 'DEL|0'; 'TRUNC|0'; 'OUT|'; return }

$src = @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

public class FsTree
{
    public static int Dirs, Files, Del, Trunc;

    class Node { public int Files; public long Bytes; public int Del; }

    static List<string> SplitCsv(string line)
    {
        var outp = new List<string>();
        var sb = new StringBuilder();
        bool inQ = false;
        for (int i = 0; i < line.Length; i++)
        {
            char ch = line[i];
            if (inQ)
            {
                if (ch == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else inQ = false;
                }
                else sb.Append(ch);
            }
            else
            {
                if (ch == '"') inQ = true;
                else if (ch == ',') { outp.Add(sb.ToString()); sb.Length = 0; }
                else sb.Append(ch);
            }
        }
        outp.Add(sb.ToString());
        return outp;
    }

    static string Size(long b)
    {
        if (b >= 1073741824L) return (b / 1073741824.0).ToString("0.0", CultureInfo.InvariantCulture) + "G";
        if (b >= 1048576L)    return (b / 1048576.0).ToString("0.0", CultureInfo.InvariantCulture) + "M";
        if (b >= 1024L)       return (b / 1024.0).ToString("0", CultureInfo.InvariantCulture) + "K";
        return b + "B";
    }

    // Folders an attacker tends to use - marked so the eye lands on them.
    // Compare the LAST PATH SEGMENT only, and by whole segment, not substring:
    // a Contains("\\temp") test matched every "templates" folder and produced 22668 marks.
    // Marking only the folder itself (not its whole subtree) keeps the tree readable.
    static readonly string[] HotSeg = { "temp", "tmp", "downloads", "public" };
    static bool Hot(string p)
    {
        int i = p.LastIndexOf('\\');
        string s = (i >= 0 ? p.Substring(i + 1) : p).ToLowerInvariant();
        if (s.Length == 0) return false;
        foreach (var h in HotSeg) if (s == h) return true;
        if (s.StartsWith("rar$")) return true;
        return false;
    }

    public static string Run(string csvPath, string outPath, int maxDepth, int maxLines)
    {
        var dirs = new Dictionary<string, Node>(StringComparer.OrdinalIgnoreCase);
        Dirs = Files = Del = Trunc = 0;

        using (var sr = new StreamReader(csvPath))
        {
            string header = sr.ReadLine();
            if (header == null) return "";
            var cols = SplitCsv(header);
            int iParent = cols.IndexOf("ParentPath");
            int iName = cols.IndexOf("FileName");
            int iDir = cols.IndexOf("IsDirectory");
            int iSize = cols.IndexOf("FileSize");
            int iInUse = cols.IndexOf("InUse");
            if (iParent < 0 || iName < 0 || iDir < 0) { Trunc = 1; return ""; }

            string line;
            while ((line = sr.ReadLine()) != null)
            {
                if (line.Length == 0) continue;
                var f = SplitCsv(line);
                if (f.Count <= iName || f.Count <= iParent) continue;
                string parent = f[iParent];
                string name = f[iName];
                if (parent.Length == 0) continue;
                if (parent[0] == '.') parent = parent.Substring(1);
                if (parent.Length == 0) parent = "\\";

                bool isDir = f[iDir] == "True";
                bool deleted = iInUse >= 0 && f.Count > iInUse && f[iInUse] == "False";

                if (isDir)
                {
                    string full = parent == "\\" ? "\\" + name : parent + "\\" + name;
                    Node nd;
                    if (!dirs.TryGetValue(full, out nd)) { nd = new Node(); dirs[full] = nd; }
                    Dirs++;
                    if (deleted) { nd.Del++; Del++; }
                }
                else
                {
                    Node nd;
                    if (!dirs.TryGetValue(parent, out nd)) { nd = new Node(); dirs[parent] = nd; }
                    nd.Files++; Files++;
                    if (iSize >= 0 && f.Count > iSize)
                    {
                        long sz;
                        if (long.TryParse(f[iSize], out sz)) nd.Bytes += sz;
                    }
                    if (deleted) { nd.Del++; Del++; }
                }
            }
        }

        // make sure every ancestor exists so the tree has no holes
        var keys = new List<string>(dirs.Keys);
        foreach (var p in keys)
        {
            var parts = p.Trim('\\').Split('\\');
            for (int d = 1; d < parts.Length; d++)
            {
                string anc = "\\" + string.Join("\\", parts, 0, d);
                if (!dirs.ContainsKey(anc)) dirs[anc] = new Node();
            }
        }

        var all = new List<string>(dirs.Keys);
        all.Sort(StringComparer.OrdinalIgnoreCase);

        int written = 0;
        using (var sw = new StreamWriter(outPath, false, new UTF8Encoding(false)))
        {
            sw.WriteLine("FILE SYSTEM TREE   (source: $MFT via MFTECmd)");
            sw.WriteLine("Generated: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sw.WriteLine("Source CSV: " + Path.GetFileName(csvPath));
            sw.WriteLine();
            sw.WriteLine("Legend:  <n files, size> per folder   [DEL n] deleted entries   (*) attacker-favoured path");
            sw.WriteLine("Deleted entries come from the MFT - a live directory listing cannot show them.");
            sw.WriteLine("Per-file detail stays in the MFTECmd CSV; this is the folder structure.");
            sw.WriteLine("Note: the volume root size looks huge because NTFS metafiles ($BadClus:$Bad etc)");
            sw.WriteLine("      are sparse and are recorded with the size of the whole volume.");
            sw.WriteLine(new string('=', 78));

            foreach (var p in all)
            {
                if (written >= maxLines) { Trunc = 1; break; }
                var parts = p.Trim('\\').Split('\\');
                int depth = parts.Length - 1;
                if (depth >= maxDepth) continue;
                string indent = depth > 0 ? new StringBuilder().Insert(0, "|  ", depth - 1) + "+-- " : "";
                var nd = dirs[p];
                string meta = "";
                if (nd.Files > 0) meta = "  <" + nd.Files + " files, " + Size(nd.Bytes) + ">";
                if (nd.Del > 0) meta += "  [DEL " + nd.Del + "]";
                // the volume root has an empty name in the MFT - show it as a drive root
                string label = parts[parts.Length - 1];
                if (label.Length == 0) label = "[volume root]";
                sw.WriteLine(indent + label + (Hot(p) ? " (*)" : "") + meta);
                written++;
            }
            if (Trunc == 1)
            {
                sw.WriteLine();
                sw.WriteLine("[!] TRUNCATED at " + maxLines + " lines - the volume has more folders than the cap.");
            }
        }
        return outPath;
    }
}
'@

try { Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop } catch {
    'DIRS|0'; 'FILES|0'; 'DEL|0'; 'TRUNC|1'; 'OUT|'; return
}

$res = ''
try { $res = [FsTree]::Run($csv.FullName, $OutFile, $MaxDepth, $MaxLines) } catch { $res = '' }

'DIRS|' + [FsTree]::Dirs
'FILES|' + [FsTree]::Files
'DEL|' + [FsTree]::Del
'TRUNC|' + [FsTree]::Trunc
'OUT|' + $res
}

# ---------------- find_suspicious.ps1 ----------------
function Invoke-VaoSuspicious {
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
if (-not $csv) { 'TOTAL|0'; 'TRUNC|0'; 'OUT|'; return }

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
    'TOTAL|0'; 'TRUNC|1'; 'OUT|'; return
}

$res = ''
if (-not $OutCsv) { $OutCsv = [System.IO.Path]::ChangeExtension($OutFile, '.csv') }
try { $res = [Suspects]::Run($csv.FullName, $OutFile, $PerCategory, $OutCsv) } catch { $res = '' }

'TOTAL|' + [Suspects]::Total
foreach ($c in [Suspects]::Counts) { 'CAT|' + $c }
'TRUNC|' + [Suspects]::Trunc
'OUT|' + $res
}

# ---------------- hash_targets.ps1 ----------------
function Invoke-VaoHashes {
param(
    [string]$SuspectCsv = "",
    [string]$Drive      = "C",
    [string]$OutCsv     = "",
    [int]$MaxFiles      = 4000,
    [int]$MaxFileMB     = 512,
    [int]$MaxSeconds    = 300
)
# Hash exactly the files the MFT pass already FLAGGED (suspicious_files.csv), so the bot can
# check them against reputation databases. Hashing the whole volume is pointless: hours of
# I/O for noise. Everything here is bounded - file count, per-file size and a time budget -
# so this step can never turn into another runaway like the Telegram target did.
# Emits SHA256 + SHA1 + MD5 on purpose, because the databases disagree:
#   SHA-1   -> CIRCL/NSRL known-GOOD bloom filter
#   SHA-256 -> MalwareBazaar known-BAD
#   MD5     -> legacy sets (ClamAV and older hash sets)
# Works for a mounted image too: MFT paths are volume-relative, so they are prefixed with the
# chosen drive letter rather than assumed to be C:.
# ASCII-ONLY: PS 5.1 reading a BOM-less file breaks on non-ASCII literals.
# stdout: HASHED|n  SKIPPED|n  MB|n  TRUNC|0|1  OUT|<path>

if (-not $SuspectCsv) { 'HASHED|0'; 'SKIPPED|0'; 'MB|0'; 'TRUNC|0'; 'OUT|'; return }
if (-not (Test-Path $SuspectCsv)) { 'HASHED|0'; 'SKIPPED|0'; 'MB|0'; 'TRUNC|0'; 'OUT|'; return }
if (-not $OutCsv) { $OutCsv = Join-Path (Split-Path $SuspectCsv -Parent) 'hashes.csv' }

$drv = $Drive.TrimEnd(':')
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$maxBytes = [long]$MaxFileMB * 1MB

$sha256 = [System.Security.Cryptography.SHA256]::Create()
$sha1   = [System.Security.Cryptography.SHA1]::Create()
$md5    = [System.Security.Cryptography.MD5]::Create()

function Hex($bytes) { ($bytes | ForEach-Object { $_.ToString('x2') }) -join '' }

$rows = New-Object System.Collections.ArrayList
$hashed = 0; $skipped = 0; $trunc = 0
$bytesRead = [long]0
$seen = New-Object System.Collections.Generic.HashSet[string]

try {
    $items = Import-Csv $SuspectCsv -ErrorAction Stop
} catch {
    'HASHED|0'; 'SKIPPED|0'; 'MB|0'; 'TRUNC|1'; 'OUT|'; return
}

foreach ($it in $items) {
    if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $trunc = 1; break }
    if ($hashed -ge $MaxFiles) { $trunc = 1; break }

    $rel = [string]$it.Path
    if (-not $rel) { continue }
    # MFT paths are volume-relative ("\Users\x\...") - bind them to the collected drive
    $full = if ($rel -match '^[A-Za-z]:') { $rel } else { $drv + ':' + $rel }
    if (-not $seen.Add($full.ToLowerInvariant())) { continue }   # same file, several categories

    try {
        $fi = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    } catch { $skipped++; continue }                              # deleted / unreadable
    if ($fi.PSIsContainer) { continue }
    if ($fi.Length -gt $maxBytes) { $skipped++; continue }

    try {
        $fs = [System.IO.File]::Open($full, 'Open', 'Read', 'ReadWrite')
        $buf = New-Object byte[] 1048576
        $sha256.Initialize(); $sha1.Initialize(); $md5.Initialize()
        while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
            [void]$sha256.TransformBlock($buf, 0, $n, $null, 0)
            [void]$sha1.TransformBlock($buf, 0, $n, $null, 0)
            [void]$md5.TransformBlock($buf, 0, $n, $null, 0)
            $bytesRead += $n
        }
        [void]$sha256.TransformFinalBlock($buf, 0, 0)
        [void]$sha1.TransformFinalBlock($buf, 0, 0)
        [void]$md5.TransformFinalBlock($buf, 0, 0)
        $fs.Close()

        [void]$rows.Add([PSCustomObject]@{
            Path      = $full
            FileName  = $fi.Name
            SizeBytes = $fi.Length
            SHA256    = Hex $sha256.Hash
            SHA1      = Hex $sha1.Hash
            MD5       = Hex $md5.Hash
            Category  = [string]$it.Category
            Note      = [string]$it.Note
            Modified  = $fi.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            Source    = 'targeted'
        })
        $hashed++
    } catch { $skipped++ }
}

try {
    if ($rows.Count -eq 0) {
        # still write a header so the bot always finds a well-formed table
        'Path,FileName,SizeBytes,SHA256,SHA1,MD5,Category,Note,Modified,Source' |
            Out-File -FilePath $OutCsv -Encoding utf8
    } else {
        $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv -ErrorAction Stop
    }
} catch {}

'HASHED|' + $hashed
'SKIPPED|' + $skipped
'MB|' + [math]::Round($bytesRead / 1MB, 1)
'TRUNC|' + $trunc
'OUT|' + $OutCsv
}

# ---------------- hunt_encrypted.ps1 ----------------
function Invoke-VaoEncrypted {
param(
    [string]$Drive = "C",
    [string]$OutCsv = "$env:TEMP\_dfir_encfiles.csv",
    [int]$MaxSeconds = 240,
    [int]$MinContainerMB = 5,
    [int]$Deep = 0,
    [string]$ScanRoot = ""
)
# Hunt DORMANT encryption on disk: encrypted containers, encrypted archives/documents and
# encryption-tool artifacts. check_encryption.ps1 finds ACTIVE/mounted encryption; this finds
# the files sitting on the disk. Same ground as Magnet EDD / Elcomsoft EEDH / Passware
# Encryption Analyzer, but ours - no third-party binary, no licence, our own output format.
# ASCII-ONLY on purpose: PS 5.1 reading a BOM-less file breaks on non-ASCII literals.
# stdout contract: CONT|n  ARCH|n  DOC|n  TOOL|n  TRUNC|0|1  SCANNED|n  CSV|<path>

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$rows = New-Object System.Collections.ArrayList
$truncated = 0
$scanned = 0

function Add-Hit($cat, $path, $size, $ent, $reason) {
    [void]$rows.Add([PSCustomObject]@{
        Category = $cat
        Path     = $path
        SizeMB   = [math]::Round($size / 1MB, 2)
        Entropy  = $ent
        Reason   = $reason
    })
}

# Extensions that are UNAMBIGUOUSLY tied to encryption tools / containers.
# Deliberately NOT here (proven false positives on a real host):
#   .vc  -> also a Visual C nmake makefile (tcl\nmake\rules.vc, targets.vc)
#   .enc -> also Tcl encoding tables (cp936.enc, big5.enc; entropy ~3.5) - see $weakExt
$toolExt = @{
    '.hc' = 'VeraCrypt container'; '.tc' = 'TrueCrypt container'
    '.kdbx' = 'KeePass database'; '.kdb' = 'KeePass database'
    '.axx' = 'AxCrypt file'; '.gpg' = 'GnuPG file'; '.pgp' = 'PGP file'
    '.pfx' = 'PKCS#12 key store'; '.p12' = 'PKCS#12 key store'
    '.luks' = 'LUKS volume'
    '.bc' = 'BestCrypt container'; '.jbc' = 'BestCrypt container'
    '.cryptomator' = 'Cryptomator vault'; '.sdsk' = 'SecureDoc container'
}
# Generic extensions: only count them when the CONTENT actually looks encrypted.
$weakExt = @{ '.enc' = 'encrypted file'; '.aes' = 'AES file' }
# High-entropy by nature -> never a container candidate (kills the obvious false positives).
$skipExt = @(
    '.zip','.7z','.rar','.gz','.bz2','.xz','.cab','.msi','.iso','.jpg','.jpeg','.png','.gif',
    '.bmp','.webp','.mp3','.mp4','.avi','.mkv','.mov','.wmv','.flac','.m4a','.pdf','.docx',
    '.xlsx','.pptx','.exe','.dll','.sys','.cat','.pak','.vmdk','.vhd','.vhdx','.vdi','.ost',
    '.pst','.edb','.wim','.esd','.dmp','.bin.gz','.crx','.jar','.apk','.woff','.woff2'
)
# First-bytes magic of well-known formats. A container has NO magic - that is the point.
$magics = @(
    @(0x50,0x4B), @(0x52,0x61,0x72,0x21), @(0x37,0x7A,0xBC,0xAF), @(0x1F,0x8B),
    @(0x89,0x50,0x4E,0x47), @(0xFF,0xD8,0xFF), @(0x47,0x49,0x46,0x38),
    @(0x25,0x50,0x44,0x46), @(0x4D,0x5A), @(0x4D,0x53,0x43,0x46),
    @(0xD0,0xCF,0x11,0xE0), @(0x53,0x51,0x4C,0x69), @(0x72,0x65,0x67,0x66),
    @(0x49,0x44,0x33), @(0x42,0x4D), @(0x7F,0x45,0x4C,0x46), @(0x00,0x01,0x00,0x00)
)

function Test-Magic([byte[]]$head) {
    foreach ($m in $magics) {
        $ok = $true
        for ($i = 0; $i -lt $m.Count; $i++) {
            if ($head.Count -le $i -or $head[$i] -ne $m[$i]) { $ok = $false; break }
        }
        if ($ok) { return $true }
    }
    # mp4/mov: 'ftyp' at offset 4
    if ($head.Count -ge 8 -and $head[4] -eq 0x66 -and $head[5] -eq 0x74 -and
        $head[6] -eq 0x79 -and $head[7] -eq 0x70) { return $true }
    return $false
}

function Get-SampleEntropy($path, $size) {
    # Sample 3 x 32KB (start / middle / end) instead of reading whole multi-GB files.
    try {
        $fs = [System.IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        $chunk = 32768
        $counts = New-Object 'int[]' 256
        $total = 0
        $offsets = @(0)
        if ($size -gt ($chunk * 3)) { $offsets = @(0, [long]($size / 2), [long]($size - $chunk)) }
        foreach ($off in $offsets) {
            $fs.Seek($off, 'Begin') | Out-Null
            $buf = New-Object byte[] $chunk
            $n = $fs.Read($buf, 0, $chunk)
            for ($i = 0; $i -lt $n; $i++) { $counts[$buf[$i]]++ }
            $total += $n
        }
        $fs.Close()
        if ($total -eq 0) { return -1 }
        $e = 0.0
        foreach ($c in $counts) {
            if ($c -gt 0) { $p = $c / $total; $e -= $p * [math]::Log($p, 2) }
        }
        return [math]::Round($e, 3)
    } catch { return -1 }
}

function Get-Head($path, $n) {
    try {
        $fs = [System.IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        $buf = New-Object byte[] $n
        $r = $fs.Read($buf, 0, $n)
        $fs.Close()
        if ($r -lt $n) { return $buf[0..([math]::Max($r - 1, 0))] }
        return $buf
    } catch { return @() }
}

# ---------------- scope ----------------
$roots = @()
$d = $Drive.TrimEnd(':') + ':\'
foreach ($sub in @('Users', 'ProgramData', 'Temp')) {
    $p = Join-Path $d $sub
    if (Test-Path $p) { $roots += $p }
}
if ($Deep -eq 1) { $roots = @($d) }
if ($ScanRoot) { $roots = @($ScanRoot) }   # test/override hook
# always look at the drive root itself (containers are often dropped there)
$rootFiles = @()
if (-not $ScanRoot) {
    try { $rootFiles = Get-ChildItem $d -File -Force -ErrorAction SilentlyContinue } catch {}
}

# NOTE: AppData\Local\Temp is deliberately NOT skipped - containers and encrypted archives
# get stashed there. Only genuinely useless high-volume caches are excluded.
$skipDirRe = '\\(Windows\\(WinSxS|Installer|assembly|servicing)|node_modules|' +
             'Program Files\\WindowsApps|AppData\\Local\\Packages\\[^\\]+\\LocalCache|' +
             'AppData\\Local\\Microsoft\\Windows\\INetCache)'

$files = New-Object System.Collections.ArrayList
foreach ($f in $rootFiles) { [void]$files.Add($f) }
foreach ($r in $roots) {
    if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $truncated = 1; break }
    try {
        Get-ChildItem $r -Recurse -File -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $truncated = 1; return }
                if ($_.FullName -notmatch $skipDirRe) { [void]$files.Add($_) }
            }
    } catch {}
}

# ---------------- classify ----------------
foreach ($f in $files) {
    if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $truncated = 1; break }
    $scanned++
    $ext = $f.Extension.ToLower()

    # 1) encryption-tool artifacts (cheap, extension only)
    if ($toolExt.ContainsKey($ext)) {
        Add-Hit 'tool_artifact' $f.FullName $f.Length '' $toolExt[$ext]
        continue
    }
    # 1b) generic extensions must PROVE they are encrypted (kills Tcl .enc tables)
    if ($weakExt.ContainsKey($ext)) {
        if ($f.Length -ge 4096) {
            $we = Get-SampleEntropy $f.FullName $f.Length
            if ($we -ge 7.5) {
                Add-Hit 'tool_artifact' $f.FullName $f.Length $we ($weakExt[$ext] + ' (entropy ' + $we + ')')
            }
        }
        continue
    }
    # 1c) PGP armored text: only when the header really says so
    if ($ext -eq '.asc' -or $ext -eq '.sig') {
        $h = Get-Head $f.FullName 64
        if ($h.Count -gt 0) {
            $s = [System.Text.Encoding]::ASCII.GetString($h)
            if ($s -match 'BEGIN PGP') {
                Add-Hit 'tool_artifact' $f.FullName $f.Length '' 'PGP armored block'
            }
        }
        continue
    }

    # 2) encrypted ZIP (general purpose bit 0 of the local file header)
    if ($ext -eq '.zip' -or $ext -eq '.docx' -or $ext -eq '.xlsx' -or $ext -eq '.pptx') {
        $h = Get-Head $f.FullName 10
        if ($h.Count -ge 8 -and $h[0] -eq 0x50 -and $h[1] -eq 0x4B -and (($h[6] -band 0x01) -eq 1)) {
            Add-Hit 'encrypted_archive' $f.FullName $f.Length '' 'ZIP with encryption flag set'
        }
        continue
    }
    # 2b) encrypted RAR4 (header flag 0x0004)
    if ($ext -eq '.rar') {
        $h = Get-Head $f.FullName 24
        if ($h.Count -ge 24 -and $h[0] -eq 0x52 -and $h[1] -eq 0x61 -and $h[2] -eq 0x72 -and $h[3] -eq 0x21) {
            if (($h[10] -band 0x04) -eq 4) {
                Add-Hit 'encrypted_archive' $f.FullName $f.Length '' 'RAR with password flag'
            }
        }
        continue
    }

    # 3) encrypted Office (OLE CFB) / PDF
    if ($ext -eq '.doc' -or $ext -eq '.xls' -or $ext -eq '.ppt' -or $ext -eq '.msg') {
        $h = Get-Head $f.FullName 8
        if ($h.Count -ge 4 -and $h[0] -eq 0xD0 -and $h[1] -eq 0xCF -and $h[2] -eq 0x11 -and $h[3] -eq 0xE0) {
            try {
                $raw = [System.IO.File]::ReadAllBytes($f.FullName)
                $s = [System.Text.Encoding]::Unicode.GetString($raw[0..([math]::Min($raw.Length - 1, 65535))])
                if ($s -match 'EncryptedPackage|EncryptionInfo') {
                    Add-Hit 'encrypted_document' $f.FullName $f.Length '' 'OLE container with EncryptedPackage'
                }
            } catch {}
        }
        continue
    }
    if ($ext -eq '.pdf') {
        try {
            $raw = Get-Head $f.FullName 4096
            $s = [System.Text.Encoding]::ASCII.GetString($raw)
            if ($s -match '/Encrypt') {
                Add-Hit 'encrypted_document' $f.FullName $f.Length '' 'PDF with /Encrypt'
            }
        } catch {}
        continue
    }

    # 4) container candidate: big, 512-aligned, no magic, near-maximum entropy
    if ($f.Length -lt ($MinContainerMB * 1MB)) { continue }
    if ($skipExt -contains $ext) { continue }
    if (($f.Length % 512) -ne 0) { continue }
    $head = Get-Head $f.FullName 16
    if ($head.Count -lt 16) { continue }
    if (Test-Magic $head) { continue }
    $ent = Get-SampleEntropy $f.FullName $f.Length
    if ($ent -ge 7.95) {
        $why = 'no file signature, 512-aligned, entropy ' + $ent + ' (VeraCrypt/TrueCrypt-like)'
        Add-Hit 'container_candidate' $f.FullName $f.Length $ent $why
    }
}

$cont = @($rows | Where-Object { $_.Category -eq 'container_candidate' }).Count
$arch = @($rows | Where-Object { $_.Category -eq 'encrypted_archive' }).Count
$doc  = @($rows | Where-Object { $_.Category -eq 'encrypted_document' }).Count
$tool = @($rows | Where-Object { $_.Category -eq 'tool_artifact' }).Count

try {
    $dir = Split-Path $OutCsv -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ($rows.Count -eq 0) { Add-Hit 'None' '-' 0 '' 'no encrypted files or containers found' }
    $rows | Sort-Object Category, @{Expression = 'SizeMB'; Descending = $true } |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv -ErrorAction Stop
} catch {}

'CONT|' + $cont
'ARCH|' + $arch
'DOC|' + $doc
'TOOL|' + $tool
'TRUNC|' + $truncated
'SCANNED|' + $scanned
'CSV|' + $OutCsv
}

# ---------------- collect_motw.ps1 ----------------
function Invoke-VaoMotw {
param(
    [Parameter(Mandatory=$true)][string]$Drive,
    [Parameter(Mandatory=$true)][string]$OutDir
)
$ErrorActionPreference = 'SilentlyContinue'
$Drive = $Drive.TrimEnd(':')
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outCsv = Join-Path $OutDir 'motw_zone_identifier.csv'

# High-signal locations where downloaded files (and their MOTW) live. Bounded for speed.
$rel = @(
    'Downloads', 'Desktop', 'Documents',
    'AppData\Local\Temp',
    'AppData\Local\Microsoft\Windows\INetCache\IE',
    'AppData\Roaming\Microsoft\Windows\Recent'
)
$roots = @()
Get-ChildItem "$Drive`:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    foreach ($r in $rel) { $p = Join-Path $_.FullName $r; if (Test-Path $p) { $roots += $p } }
}

$rows = New-Object System.Collections.Generic.List[object]
foreach ($root in $roots) {
    Get-ChildItem -Path $root -Recurse -File -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Length -lt 524288000 } | ForEach-Object {
        $f = $_
        $zi = Get-Content -LiteralPath $f.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
        if ($zi) {
            $text = ($zi -join "`n")
            $zid  = ([regex]::Match($text, '(?im)^\s*ZoneId\s*=\s*(.+?)\s*$')).Groups[1].Value
            $host_= ([regex]::Match($text, '(?im)^\s*HostUrl\s*=\s*(.+?)\s*$')).Groups[1].Value
            $ref  = ([regex]::Match($text, '(?im)^\s*ReferrerUrl\s*=\s*(.+?)\s*$')).Groups[1].Value
            # Ingest only rows with provenance (HostUrl or ReferrerUrl), per the contract.
            if ($host_ -or $ref) {
                $rows.Add([pscustomobject]@{
                    Path        = $f.FullName
                    ZoneId      = $zid
                    HostUrl     = $host_
                    ReferrerUrl = $ref
                    Timestamp   = $f.LastWriteTimeUtc.ToString('o')
                })
            }
        }
    }
}

if ($rows.Count -gt 0) {
    $rows | Export-Csv -LiteralPath $outCsv -NoTypeInformation -Encoding UTF8
    Write-Output ("MOTW: wrote {0} rows -> {1}" -f $rows.Count, $outCsv)
} else {
    # still emit a header-only CSV so the bot's folder routing is consistent
    'Path,ZoneId,HostUrl,ReferrerUrl,Timestamp' | Set-Content -LiteralPath $outCsv -Encoding UTF8
    Write-Output "MOTW: no Zone.Identifier provenance found (empty CSV written)"
}
}

# ---------------- collect_liveresponse.ps1 ----------------
function Invoke-VaoLiveResponse {
param(
    [string]$OutDir = "",
    [int]$MaxSeconds = 180
)
# Live snapshot of the RUNNING system: what is executing right now and who it talks to.
# WHY THIS EXISTS: the disk tells us what ran at some point (Prefetch, Amcache, ShimCache).
# It does NOT tell us what is running NOW and which process holds a connection. For an
# incident where the malicious process is still alive, that is the decisive evidence.
# REPLACES A THIRD-PARTY TOOL: CurrPorts/cports shows which process owns a connection. We
# already captured OwningProcess (the PID); everything else is a PID->process join, so this
# is written with built-in APIs instead of shipping another binary. A NirSoft utility once
# hung the whole collector, so avoiding one is a feature.
# LIVE ONLY. On a mounted image these objects belong to the EXAMINER's workstation.
# ASCII-ONLY: PS 5.1 reading a BOM-less file breaks on non-ASCII literals.
# stdout: PROC|n  CONN|n  PIPE|n  SVC|n  SESS|n  TRUNC|0|1

if (-not $OutDir) { 'PROC|0'; 'CONN|0'; 'PIPE|0'; 'SVC|0'; 'SESS|0'; 'TRUNC|0'; return }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$trunc = 0
$script:counts = @{ PROC = 0; CONN = 0; PIPE = 0; SVC = 0; SESS = 0 }

function Save($rows, $name, $key) {
    try {
        if ($rows) {
            $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir $name)
            $script:counts[$key] = @($rows).Count
        }
    } catch {}
}

# ---------------- processes: tree + command line + signature ----------------
# The command line is the single most valuable field here: a phishing chain shows up as
# winword.exe -> cmd.exe -> powershell -enc <base64> without any further analysis.
$procMap = @{}
try {
    $raw = Get-CimInstance Win32_Process -ErrorAction Stop |
           Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
    foreach ($p in $raw) { $procMap[[int]$p.ProcessId] = $p }

    $rows = foreach ($p in $raw) {
        if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $trunc = 1; break }
        $parent = $procMap[[int]$p.ParentProcessId]
        $sig = ''
        if ($p.ExecutablePath) {
            try { $sig = (Get-AuthenticodeSignature -LiteralPath $p.ExecutablePath -ErrorAction Stop).Status } catch { $sig = 'Unknown' }
        }
        [PSCustomObject]@{
            PID          = $p.ProcessId
            ParentPID    = $p.ParentProcessId
            Name         = $p.Name
            ParentName   = if ($parent) { $parent.Name } else { '' }
            Path         = $p.ExecutablePath
            CommandLine  = $p.CommandLine
            Started      = $p.CreationDate
            Signature    = $sig
        }
    }
    Save $rows 'processes.csv' 'PROC'
} catch {}

# ---------------- network: TCP + UDP WITH process attribution ----------------
try {
    $conns = @()
    try {
        $conns += Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            $p = $procMap[[int]$_.OwningProcess]
            [PSCustomObject]@{
                Proto         = 'TCP'
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort    = $_.RemotePort
                State         = $_.State
                PID           = $_.OwningProcess
                ProcessName   = if ($p) { $p.Name } else { '' }
                ProcessPath   = if ($p) { $p.ExecutablePath } else { '' }
                CommandLine   = if ($p) { $p.CommandLine } else { '' }
            }
        }
    } catch {}
    try {
        $conns += Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            $p = $procMap[[int]$_.OwningProcess]
            [PSCustomObject]@{
                Proto         = 'UDP'
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                RemoteAddress = ''
                RemotePort    = ''
                State         = ''
                PID           = $_.OwningProcess
                ProcessName   = if ($p) { $p.Name } else { '' }
                ProcessPath   = if ($p) { $p.ExecutablePath } else { '' }
                CommandLine   = if ($p) { $p.CommandLine } else { '' }
            }
        }
    } catch {}
    Save $conns 'connections.csv' 'CONN'
} catch {}

# ---------------- named pipes ----------------
# C2 frameworks create characteristic named pipes; the list is small and cheap to take.
try {
    $pipes = Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue |
             Select-Object @{n = 'Pipe'; e = { $_.Name } }
    Save $pipes 'named_pipes.csv' 'PIPE'
} catch {}

# ---------------- services with binary path + state ----------------
try {
    $svc = Get-CimInstance Win32_Service -ErrorAction Stop |
           Select-Object Name, DisplayName, State, StartMode, PathName, ProcessId, StartName
    Save $svc 'services.csv' 'SVC'
} catch {}

# ---------------- logged-on sessions and SMB ----------------
try {
    $sess = @()
    try {
        $sess += Get-CimInstance Win32_LoggedOnUser -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Kind = 'LoggedOnUser'; Detail = $_.Antecedent }
        }
    } catch {}
    try {
        $sess += Get-SmbSession -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Kind = 'SmbSession'; Detail = ($_.ClientComputerName.ToString() + ' / ' + $_.ClientUserName) }
        }
    } catch {}
    try {
        $sess += Get-SmbShare -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Kind = 'SmbShare'; Detail = ($_.Name + ' -> ' + $_.Path) }
        }
    } catch {}
    Save $sess 'sessions.csv' 'SESS'
} catch {}

if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $trunc = 1 }

'PROC|' + $script:counts.PROC
'CONN|' + $script:counts.CONN
'PIPE|' + $script:counts.PIPE
'SVC|' + $script:counts.SVC
'SESS|' + $script:counts.SESS
'TRUNC|' + $trunc
}

# ------------------------------ dispatcher ------------------------------------
# One process, the same order and outputs the six separate scripts had.
# Guarded on purpose: dot-sourcing this file must only DEFINE the functions. Without the
# guard a dot-source runs every step with empty parameters, each step hits its own
# "no OutDir" early exit, and the caller sees a row of zeros - which is exactly what
# happened the first time this was tested.
if (-not $OutDir) { return }

# parameters come from the param() block above


$IsLive = [bool]$Live

Write-Output "VAO_STEP fs_tree"
Invoke-VaoFsTree -CsvDir $CsvDir -OutFile (Join-Path $OutDir 'filesystem_tree.txt')

Write-Output "VAO_STEP suspicious"
Invoke-VaoSuspicious -CsvDir $CsvDir -OutFile (Join-Path $OutDir 'suspicious_files.txt') `
                     -OutCsv (Join-Path $OutDir 'suspicious_files.csv')

Write-Output "VAO_STEP hashes"
Invoke-VaoHashes -SuspectCsv (Join-Path $OutDir 'suspicious_files.csv') -Drive $Drive `
                 -OutCsv (Join-Path $OutDir 'hashes.csv')

Write-Output "VAO_STEP encrypted"
Invoke-VaoEncrypted -Drive $Drive -OutCsv (Join-Path $OutDir 'encrypted_files.csv') -MaxSeconds 240

Write-Output "VAO_STEP motw"
Invoke-VaoMotw -Drive $Drive -OutDir (Join-Path $OutDir 'motw')

if ($IsLive) {
    Write-Output "VAO_STEP liveresponse"
    Invoke-VaoLiveResponse -OutDir (Join-Path $OutDir 'live\system')
}
Write-Output "VAO_STEP done"
