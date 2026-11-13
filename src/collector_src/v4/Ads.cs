// Alternate data streams on the target disk.
//
// Why (23.10.2026): two notary cases had a stream \ProgramData\TEMP:<hex> on a FOLDER. The bot
// found it from the $MFT listing (MFTECmd shows the stream name and size), but the archive
// held no byte of it, so nobody could say what was hidden there. MFTECmd cannot give the
// content and KAPE has no target for "every stream", hence this step.
//
// What it does: walks the places malware and installers actually use (drive root, ProgramData,
// user profiles, Windows\Temp, Public), lists every named stream on files AND folders, skips
// the well-known benign ones, and for the rest writes one CSV row plus, up to 1 MB, the
// stream's bytes to ads\NNNN.bin. The archive is AES-encrypted and the work folder has a
// Defender exclusion, so a payload hidden in a stream survives the trip to the bot.
// Target-disk step -> runs in both scenarios (live host and mounted image).

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

static class Ads
{
    const long MAX_SAVE = 1024 * 1024;          // owner's limit: content up to 1 MB
    const int MAX_ROWS = 5000;                  // a stream-heavy box must not flood the CSV
    const int MAX_SAVED = 500;

    // Streams Windows, browsers, Office and sync clients write on their own. Recorded only as
    // a count: Zone.Identifier is already collected by the MOTW step.
    static readonly HashSet<string> BENIGN = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
        "Zone.Identifier", "SmartScreen", "encryptable", "favicon", "Afp_AfpInfo", "AFP_AfpInfo",
        "AFP_Resource", "com.dropbox.attributes", "com.dropbox.attrs", "ms-properties",
        "OECustomProperty", "Win32App_1", "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",
        "\u0005SummaryInformation", "\u0005DocumentSummaryInformation", "\u0005Q30lsldxJoudresxAaaqpcawXc",
        "\u0005Rfsuj3ilEtvd1yslPceb5ddVc", "\u0005Ebiqnnmdiq3wpbctPjltryy4Ab", "CA_INOCULATEIT", "KAVICHS",
        "TaskbarPinned", "Zone.Identifier:$DATA", "$CmdTcID", "$CmdZnID", "MBAM.Scanned",
        "OneDriveUserSyncState", "com.apple.quarantine", "com.apple.lastuseddate#PS",
        "com.apple.metadata:kMDItemWhereFroms", "AppleDouble", "TOC.WMV", "DFSR",
    };

    public sealed class Result { public int Seen, Benign, Rows, Saved; public bool Truncated; public string Why = ""; }

    public static Result Scan(string drive, string outDir, bool full, Action<string, string> gap)
    {
        Result r = new Result();
        string root = drive.TrimEnd(':', '\\') + @":\";
        string csv = Path.Combine(outDir, "ads_streams.csv");
        string binDir = Path.Combine(outDir, "ads");
        DateTime stop = DateTime.Now.AddMinutes(full ? 20 : 6);

        // (folder, depth) - depth 0 = the folder itself and its direct children
        List<KeyValuePair<string, int>> roots = new List<KeyValuePair<string, int>>();
        roots.Add(new KeyValuePair<string, int>(root, 0));
        roots.Add(new KeyValuePair<string, int>(root + "ProgramData", full ? 6 : 4));
        roots.Add(new KeyValuePair<string, int>(root + @"Windows\Temp", 4));
        roots.Add(new KeyValuePair<string, int>(root + @"Windows\Tasks", 1));
        roots.Add(new KeyValuePair<string, int>(root + @"Users\Public", 5));
        foreach (string u in Arr(Lp.Dirs(root + "Users")))
        {
            string n = Path.GetFileName(u);
            if (n.Equals("Public", StringComparison.OrdinalIgnoreCase)) continue;
            // "All Users" -> ProgramData, "Default User" -> Default: links, already covered
            try { if ((File.GetAttributes(Lp.P(u)) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
            roots.Add(new KeyValuePair<string, int>(Path.Combine(u, "AppData"), full ? 7 : 5));
            foreach (string sub in new string[] { "Desktop", "Downloads", "Documents", "Music", "Videos", "Pictures" })
                roots.Add(new KeyValuePair<string, int>(Path.Combine(u, sub), full ? 5 : 3));
            roots.Add(new KeyValuePair<string, int>(u, 0));
        }

        StreamWriter w = null;
        try
        {
            Directory.CreateDirectory(outDir);
            w = new StreamWriter(csv, false, new UTF8Encoding(false));
            w.WriteLine("Path,Stream,Size,IsFolder,SHA256,SavedAs,Head");
            HashSet<string> done = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, int> kv in roots)
            {
                if (!Lp.DirExists(kv.Key)) continue;
                if (!Walk(kv.Key, kv.Value, true, done, w, binDir, r, stop)) break;
            }
        }
        catch (Exception ex) { r.Why = Lp.Human(ex); }
        finally { if (w != null) try { w.Close(); } catch { } }

        if (r.Truncated)
            gap("потоки ADS", "обхід зупинено за лімітом (час або " + MAX_ROWS + " рядків) - зібрано частину");
        if (r.Why.Length > 0) gap("потоки ADS", r.Why);
        return r;
    }

    // returns false when the time/row budget ran out
    static bool Walk(string dir, int depth, bool includeSelf, HashSet<string> done, StreamWriter w,
                     string binDir, Result r, DateTime stop)
    {
        if (DateTime.Now > stop || r.Rows >= MAX_ROWS) { r.Truncated = true; return false; }
        if (!done.Add(dir)) return true;
        if (includeSelf) Streams(dir, true, w, binDir, r);
        foreach (string f in Arr(Lp.Files(dir)))
        {
            Streams(f, false, w, binDir, r);
            if (r.Rows >= MAX_ROWS) { r.Truncated = true; return false; }
        }
        foreach (string d in Arr(Lp.Dirs(dir)))
        {
            // reparse points (junctions like "Application Data") loop back into the profile
            try { if ((File.GetAttributes(Lp.P(d)) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
            if (depth > 0) { if (!Walk(d, depth - 1, true, done, w, binDir, r, stop)) return false; }
            else Streams(d, true, w, binDir, r);     // last level: the folder's own streams still count
        }
        return true;
    }

    static void Streams(string path, bool isDir, StreamWriter w, string binDir, Result r)
    {
        foreach (KeyValuePair<string, long> s in Native.ListStreams(Long(path)))
        {
            r.Seen++;
            if (BENIGN.Contains(s.Key)) { r.Benign++; continue; }
            string sha = "", saved = "", head = "";
            if (s.Value <= MAX_SAVE && r.Saved < MAX_SAVED)
            {
                byte[] data = Native.ReadStream(Long(path) + ":" + s.Key, MAX_SAVE);
                if (data != null)
                {
                    using (SHA256 h = SHA256.Create())
                        sha = BitConverter.ToString(h.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
                    head = Head(data);
                    try
                    {
                        Directory.CreateDirectory(binDir);
                        saved = @"ads\" + (r.Saved + 1).ToString("D4") + ".bin";
                        File.WriteAllBytes(Path.Combine(binDir, (r.Saved + 1).ToString("D4") + ".bin"), data);
                        r.Saved++;
                    }
                    catch { saved = ""; }
                }
            }
            w.WriteLine(string.Join(",", new string[] {
                Q(Lp.Plain(path)), Q(s.Key), s.Value.ToString(), isDir ? "1" : "0", sha, saved, Q(head) }));
            r.Rows++;
        }
    }

    // first 48 bytes: printable as text, else hex - enough to tell MZ / script / zip / blob apart
    static string Head(byte[] d)
    {
        int n = Math.Min(48, d.Length);
        bool text = true;
        for (int i = 0; i < n; i++) { byte b = d[i]; if (b < 9 || (b > 13 && b < 32) || b == 127) { text = false; break; } }
        if (text) return Encoding.UTF8.GetString(d, 0, n).Replace("\r", " ").Replace("\n", " ");
        return "hex:" + BitConverter.ToString(d, 0, n).Replace("-", "");
    }

    static string[] Arr(string[] a) { return a ?? new string[0]; }

    // the stream APIs always get the \\?\ form: a stream name pushes a path over MAX_PATH sooner
    static string Long(string path)
    {
        string p = Lp.Plain(path);
        return p.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + p.Substring(2) : @"\\?\" + p;
    }

    static string Q(string s) { return "\"" + (s ?? "").Replace("\"", "\"\"") + "\""; }
}
