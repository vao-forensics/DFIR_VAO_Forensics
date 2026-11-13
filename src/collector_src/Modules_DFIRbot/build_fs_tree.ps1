# ==============================================================================
#  VAO_DFIR_COLLECTOR_MARKER
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : build_fs_tree.ps1
#  collector : VAO DFIR Collector v4.0
#  purpose   : file system tree from $MFT (READ-ONLY)
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
    [int]$MaxDepth = 12,
    [int]$MaxLines = 200000
)
# Build a readable file/folder TREE from the MFTECmd $MFT CSV that !EZParser already produced.
# The MFT is the forensic source: it also carries DELETED entries, which a live directory walk
# can never show. Per-file detail stays in the CSV; this renders the DIRECTORY structure with
# per-folder file counts and sizes, which is small enough for a human to read.
#
# PERFORMANCE: a real volume is ~800k MFT records / ~350 MB of CSV. A PowerShell character
# loop over that takes many minutes, so the parse + aggregate + render all happen inside a
# compiled C# type (Add-Type) and run at .NET speed.
#
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
if (-not $csv) { 'DIRS|0'; 'FILES|0'; 'DEL|0'; 'TRUNC|0'; 'OUT|'; exit 0 }

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

    // High-volume, low-relevance subtrees an examiner never reads for the folder overview.
    // The per-file detail is still in the MFTECmd CSV; this only trims the TREE so the eye
    // lands on user data, installed programs and staging areas instead of OS component stores
    // and package/build caches. Whole-segment match so "assemblyman" is not caught by "assembly".
    static readonly string[] NoiseSeg = {
        "winsxs", "driverstore", "catroot2", "assembly", "servicing", "softwaredistribution",
        "node_modules", "site-packages", "__pycache__", ".git", ".nuget", ".cargo", ".gradle",
        "gpucache", "code cache", "service worker", "cryptneturlcache", "inetcache", "cache2"
    };
    static bool Keep(string p)
    {
        foreach (var raw in p.Split('\\'))
        {
            string s = raw.ToLowerInvariant();
            foreach (var n in NoiseSeg) if (s == n) return false;
        }
        return true;
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
            sw.WriteLine("Trimmed for readability: OS component stores and package/build caches");
            sw.WriteLine("      (WinSxS, DriverStore, node_modules, site-packages, .git, ...) are omitted.");
            sw.WriteLine("Note: the volume root size looks huge because NTFS metafiles ($BadClus:$Bad etc)");
            sw.WriteLine("      are sparse and are recorded with the size of the whole volume.");
            sw.WriteLine(new string('=', 78));

            foreach (var p in all)
            {
                if (written >= maxLines) { Trunc = 1; break; }
                if (!Keep(p)) continue;
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
    'DIRS|0'; 'FILES|0'; 'DEL|0'; 'TRUNC|1'; 'OUT|'; exit 0
}

$res = ''
try { $res = [FsTree]::Run($csv.FullName, $OutFile, $MaxDepth, $MaxLines) } catch { $res = '' }

'DIRS|' + [FsTree]::Dirs
'FILES|' + [FsTree]::Files
'DEL|' + [FsTree]::Del
'TRUNC|' + [FsTree]::Trunc
'OUT|' + $res
