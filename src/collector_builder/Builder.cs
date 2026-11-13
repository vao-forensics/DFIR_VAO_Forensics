// DFIR Collector Builder - downloads the third-party tools the collector runs, compiles the
// collector with YOUR bot's public key and writes one DFIR_Collector.exe.
//
// Why a builder and not a ready EXE in the releases: KAPE, THOR Lite and Magnet DumpIt are
// licensed per user and must not be redistributed, and every bot has its own archive key.
// So each person assembles their own collector on their own Windows machine, with tools they
// downloaded themselves. csc.exe ships with every Windows (.NET Framework 4.x), nothing to install.
//
// The output has the same layout build_v4.py produces:
//     [ PE ][ zip ][ int64 zip offset ][ "DFIRPAY1" ]
// so the collector core (src/collector_src/v4) needs no change.
//
// Written in C# 5: that is the newest language the csc of .NET Framework 4.x understands.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

class BuildOptions
{
    public string SealLine = "";
    public string KapeZip = "";
    public string ThorZip = "";
    public string ThorLic = "";
    public string MemoryDir = "";
    public string OutDir = "";
    public bool Full = true;
    public bool AddExclusions = false;
    public string ToolsJson = "";   // --tools-json: a manifest file instead of the embedded one (tests, early fixes)
    public string Mirror = null;    // --mirror: overrides the embedded mirror.txt
}

class BuildFailed : Exception
{
    public BuildFailed(string m) : base(m) { }
}

class Builder
{
    const string MAGIC = "DFIRPAY1";
    // Files the collector core calls by name; a build without one of them is not a collector.
    static readonly string[] REQUIRED = {
        "kape.exe", "7za/7za.exe", "Modules/bin/vao_triage.exe",
        "Modules/!DFIRbot/vao_collect_all.ps1",
        "Targets/!DFIRbot/DFIRbot_Fast.tkape", "Targets/!DFIRbot/DFIRbot_Full.tkape",
        "Targets/!DFIRbot/DFIRbot_Comms.tkape",
    };

    readonly Action<string> _log;
    readonly Action<int> _progress;
    readonly string _work, _cache, _stage, _bin;
    readonly Dictionary<string, string> _tierOfTop = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    readonly List<string> _prov = new List<string>();
    readonly List<string> _warnings = new List<string>();
    string _mirror = "";
    Dictionary<string, string> _mirrorSums;   // name -> sha256 from {mirror}/SHA256SUMS
    string _ver = "", _digest = "";           // version/tag and author digest of the download in hand

    public List<string> Warnings { get { return _warnings; } }

    public Builder(Action<string> log, Action<int> progress)
    {
        _log = log;
        _progress = progress;
        _work = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DFIR_Builder");
        _cache = Path.Combine(_work, "cache");
        _stage = Path.Combine(_work, "stage");
        _bin = Path.Combine(_stage, "Modules", "bin");
    }

    // ---------------------------------------------------------------- entry point

    public string Run(BuildOptions o)
    {
        string kid, modulus;
        ParseSeal(o.SealLine, out kid, out modulus);
        if (!File.Exists(o.KapeZip)) throw new BuildFailed(L.T("Не вказано kape.zip (його видає Kroll після короткої форми).", "kape.zip is not set (Kroll gives it after a short form)."));
        if (string.IsNullOrEmpty(o.OutDir)) throw new BuildFailed(L.T("Не вказано теку для готового EXE.", "The folder for the finished EXE is not set."));
        string csc = FindCsc();

        Directory.CreateDirectory(_cache);
        Directory.CreateDirectory(o.OutDir);
        if (o.AddExclusions) AddDefenderExclusions(new[] { _work, o.OutDir });
        if (Directory.Exists(_stage)) Directory.Delete(_stage, true);
        Directory.CreateDirectory(_bin);

        var man = LoadManifest(o);

        Step(2, L.T("Визначення KAPE і наші модулі", "KAPE definitions and our modules"));
        ExtractZip(ResourceStream("defs.zip"), _stage, false);
        string overlay = Path.Combine(_stage, "overlay");

        Step(4, L.T("KAPE з ", "KAPE from ") + Path.GetFileName(o.KapeZip));
        TakeFromZip(o.KapeZip, "kape.exe", Path.Combine(_stage, "kape.exe"));
        Record("kape", "kape.exe", o.KapeZip);

        Step(6, "7-Zip (7za)");
        SevenZip((Dictionary<string, object>)man["sevenzip"]);

        FetchTools(man, o.Full);

        Step(80, L.T("Необов'язкові модулі", "Optional modules"));
        if (!string.IsNullOrEmpty(o.ThorZip))
        {
            string d = Path.Combine(_bin, "thor-lite");
            using (var fs = File.OpenRead(o.ThorZip)) ExtractZip(fs, d, true);
            if (File.Exists(o.ThorLic)) File.Copy(o.ThorLic, Path.Combine(d, Path.GetFileName(o.ThorLic)), true);
            else _warnings.Add(L.T("THOR Lite без .lic не запуститься", "THOR Lite will not start without a .lic"));
            _tierOfTop["thor-lite"] = "full";
            Record("thor-lite", "thor-lite\\", o.ThorZip);
        }
        if (!string.IsNullOrEmpty(o.MemoryDir) && Directory.Exists(o.MemoryDir))
        {
            string d = Path.Combine(_bin, "memory");
            Directory.CreateDirectory(d);
            foreach (string n in new[] { "DumpIt.exe", "MRCv120.exe" })
            {
                string s = Path.Combine(o.MemoryDir, n);
                if (File.Exists(s)) { File.Copy(s, Path.Combine(d, n), true); Record("memory", "memory\\" + n, s); }
            }
            _tierOfTop["memory"] = "fast";
        }

        // our corrections to stock tool files (RECmd DFIRBatch.reb) go on top of the downloads
        if (Directory.Exists(overlay))
        {
            CopyTree(overlay, _stage);
            Directory.Delete(overlay, true);
        }

        Step(84, L.T("Компіляція vao_triage і ядра збирача", "Compiling vao_triage and the collector core"));
        string src = Path.Combine(_work, "src");
        if (Directory.Exists(src)) Directory.Delete(src, true);
        ExtractZip(ResourceStream("core.zip"), src, false);
        Csc(csc, new[] { "/target:exe", "/optimize+", "/codepage:65001", "/out:" + Path.Combine(_bin, "vao_triage.exe"),
                         Path.Combine(src, "VaoTriage.cs") });
        _tierOfTop["vao_triage.exe"] = "fast";

        File.WriteAllText(Path.Combine(src, "v4", "Seal_key.cs"),
            "// GENERATED by DFIR Collector Builder - public half of the bot's archive key.\r\n" +
            "static class SealKey\r\n{\r\n" +
            "    public const string KeyId = \"" + kid + "\";\r\n" +
            "    public const string ModulusB64 = \"" + modulus + "\";\r\n" +
            "    public const string ExponentB64 = \"AQAB\";\r\n" +
            "    public const string Lang = \"" + L.Code + "\";\r\n}\r\n", new UTF8Encoding(false));
        string core = Path.Combine(_work, "core.exe");
        var args = new List<string> { "/target:exe", "/platform:anycpu", "/optimize+", "/codepage:65001",
            "/win32manifest:" + Path.Combine(src, "launcher.manifest"), "/win32icon:" + Path.Combine(src, "collector.ico"),
            "/reference:System.Management.dll", "/reference:System.IO.Compression.dll",
            "/reference:System.IO.Compression.FileSystem.dll", "/out:" + core };
        args.AddRange(Directory.GetFiles(Path.Combine(src, "v4"), "*.cs"));
        Csc(csc, args.ToArray());

        Step(90, L.T("Пакую оверлей", "Packing the overlay"));
        Directory.CreateDirectory(o.OutDir);
        string final = Path.Combine(o.OutDir, "DFIR_Collector.exe");
        string zip = Path.Combine(_work, "payload.zip");
        int extra = WritePayload(zip);
        using (var outf = File.Create(final))
        {
            using (var c = File.OpenRead(core)) c.CopyTo(outf);
            long off = outf.Position;
            using (var z = File.OpenRead(zip)) z.CopyTo(outf);
            outf.Write(BitConverter.GetBytes(off), 0, 8);
            outf.Write(Encoding.ASCII.GetBytes(MAGIC), 0, 8);
        }
        File.Delete(zip);
        if (extra > 0) _log(string.Format(L.T("   {0} файлів не викликає жоден модуль - у збирач не пішли", "   {0} files are not used by any module - left out of the collector"), extra));

        Step(96, L.T("Перевірка готового EXE", "Checking the finished EXE"));
        try { Verify(final); }
        catch (IOException e)
        {
            if (!File.Exists(final) || e.Message.IndexOf("virus", StringComparison.OrdinalIgnoreCase) >= 0 || e.HResult == unchecked((int)0x800700E1))
                throw new BuildFailed(L.T("Антивірус (Windows Defender) забрав готовий збирач у карантин. Це очікувано для ", "The antivirus (Windows Defender) quarantined the finished collector. This is expected for ") +
                    L.T("непідписаного EXE з форензичними утилітами. Увімкніть «Додати винятки Defender» і зберіть ще раз ", "an unsigned EXE with forensic utilities. Tick «Add Defender exclusions» and build again ") +
                    L.T("(або додайте теки ", "(or add the folders ") + _work + L.T(" і ", " and ") + o.OutDir + L.T(" у винятки вручну).", " to the exclusions by hand)."));
            throw;
        }
        string sha = Sha256(final);
        WriteProvenance(Path.Combine(o.OutDir, "TOOLS_PROVENANCE.txt"), kid, sha);
        File.WriteAllText(Path.Combine(o.OutDir, "DFIR_Collector.exe.sha256"), sha + "  DFIR_Collector.exe\r\n");
        Step(100, string.Format(L.T("Готово: {0} ({1:N1} МБ), ключ {2}", "Done: {0} ({1:N1} MB), key {2}"), final, new FileInfo(final).Length / 1048576.0, kid));
        return final;
    }

    Dictionary<string, object> LoadManifest(BuildOptions o)
    {
        string json = o.ToolsJson != "" ? File.ReadAllText(o.ToolsJson) : ResourceText("tools.json");
        _mirror = (o.Mirror ?? ResourceText("mirror.txt")).Trim().TrimEnd('/');
        return (Dictionary<string, object>)new JavaScriptSerializer().DeserializeObject(json);
    }

    void FetchTools(Dictionary<string, object> man, bool full)
    {
        var tools = ((object[])man["tools"]).Cast<Dictionary<string, object>>().ToList();
        int i = 0;
        foreach (var t in tools)
        {
            i++;
            string tier = Str(t, "tier");
            if (tier == "full" && !full) continue;
            Step(8 + 70 * i / tools.Count, Str(t, "id"));
            try { Tool(t); }
            catch (Exception e)
            {
                _warnings.Add(Str(t, "id") + ": " + e.Message);
                _log("   ! " + e.Message + L.T(" - збирач працюватиме, але цей крок дасть порожній рядок у collection_gaps.csv", " - the collector will work, but this step gives an empty row in collection_gaps.csv"));
            }
        }
    }

    // --check-tools: fetch and verify every tool exactly as a build would (newest version, author
    // digest / pinned hash / signature, mirror fallback) but compile nothing. Returns the report.
    public string CheckTools(BuildOptions o)
    {
        Directory.CreateDirectory(_cache);
        if (Directory.Exists(_stage)) Directory.Delete(_stage, true);
        Directory.CreateDirectory(_bin);
        var man = LoadManifest(o);
        Step(6, "7-Zip (7za)");
        SevenZip((Dictionary<string, object>)man["sevenzip"]);
        FetchTools(man, o.Full);
        string rep = ProvenanceText(L.T("(перевірка, без збирання)", "(check only, nothing built)"), "-");
        if (!string.IsNullOrEmpty(o.OutDir))
        {
            Directory.CreateDirectory(o.OutDir);
            File.WriteAllText(Path.Combine(o.OutDir, "TOOLS_PROVENANCE.txt"), rep, new UTF8Encoding(true));
        }
        return rep;
    }

    void Step(int pct, string what)
    {
        _progress(pct);
        _log("== " + what);
    }

    // ---------------------------------------------------------------- seal key

    public static void ParseSeal(string line, out string kid, out string modulus)
    {
        var m = Regex.Match((line ?? "").Trim(), @"^dfir-seal-1:([0-9a-f]{16}):([A-Za-z0-9+/=]+)$");
        if (!m.Success)
            throw new BuildFailed(L.T("Ключ має вигляд dfir-seal-1:<16 hex>:<base64>. Його друкує install.sh наприкінці ", "The key looks like dfir-seal-1:<16 hex>:<base64>. install.sh prints it at the end ") +
                                  L.T("і зберігає в state/keys/collector_seal.txt на сервері бота.", "and saves it in state/keys/collector_seal.txt on the bot server."));
        kid = m.Groups[1].Value;
        modulus = m.Groups[2].Value;
        byte[] n;
        try { n = Convert.FromBase64String(modulus); }
        catch (FormatException) { throw new BuildFailed(L.T("Ключ пошкоджено: модуль не є base64.", "The key is damaged: the modulus is not base64.")); }
        if (n.Length * 8 < 3072) throw new BuildFailed(L.T("Ключ закороткий: ", "The key is too short: ") + n.Length * 8 + L.T(" біт.", " bits."));
    }

    // ---------------------------------------------------------------- tools

    // Official source first (newest release); if it is gone, changed shape or fails verification,
    // the same file is taken from the project's mirror and checked against its SHA256SUMS.
    void Tool(Dictionary<string, object> t)
    {
        string id = Str(t, "id");
        bool mirrorOnly = Str(t, "url").StartsWith("{mirror}");
        try { _ver = ""; _digest = ""; ToolFrom(t, ResolveUrl(t), mirrorOnly); }
        catch (BuildFailed e)
        {
            if (mirrorOnly || _mirror == "") throw;
            string m = _mirror + "/" + MirrorName(t);
            _log("   ! " + e.Message);
            _log(L.T("   пробую запасне дзеркало: ", "   trying the fallback mirror: ") + m);
            _ver = "mirror"; _digest = "";
            ToolFrom(t, m, true);
            _warnings.Add(id + L.T(": офіційне джерело не пройшло перевірку (", ": the official source failed (") + e.Message + L.T(") - взято перевірену копію з дзеркала", ") - a verified copy was taken from the mirror"));
        }
    }

    static string MirrorName(Dictionary<string, object> t)
    {
        string n = Str(t, "mirror_name");
        if (n != "") return n;
        string kind = Str(t, "kind");
        return Str(t, "id") + (kind == "file" ? ".exe" : kind == "msi" ? ".msi" : kind == "nupkg" ? ".nupkg" : ".zip");
    }

    void ToolFrom(Dictionary<string, object> t, string url, bool fromMirror)
    {
        string id = Str(t, "id"), kind = Str(t, "kind"), tier = Str(t, "tier");
        var how = new List<string>();
        string file = Fetch(id, url, fromMirror ? MirrorName(t) : null, how, t.ContainsKey("sha256"));
        var written = new List<string>();

        if (kind == "file")
        {
            string dst = Path.Combine(_bin, Str(t, "take"));
            Directory.CreateDirectory(Path.GetDirectoryName(dst));
            RequirePe(file, id);
            File.Copy(file, dst, true);
            written.Add(Str(t, "take"));
        }
        else if (kind == "zip" || kind == "nupkg")
        {
            string rel = Str(t, "rename");
            if (rel == "") rel = Path.GetFileName(Str(t, "take").Replace('/', '\\'));
            TakeFromZip(file, Str(t, "take"), Path.Combine(_bin, rel));
            written.Add(rel);
        }
        else if (kind == "zipdir")
        {
            string dest = Str(t, "dest");
            string d = Path.Combine(_bin, dest);
            if (Directory.Exists(d)) Directory.Delete(d, true);
            // test data and other-OS binaries we never run are not even written: chainsaw's sigma
            // regression samples carry mimikatz strings and Defender quarantines them mid-build
            var drop = t.ContainsKey("drop") ? ((object[])t["drop"]).Cast<string>().ToArray() : new string[0];
            using (var fs = File.OpenRead(file)) ExtractZip(fs, d, true, drop);
            var rg = t.ContainsKey("rename_glob") ? (Dictionary<string, object>)t["rename_glob"] : null;
            if (rg != null)
                foreach (var kv in rg)
                    foreach (string f in Directory.GetFiles(d, kv.Key))
                    {
                        string to = Path.Combine(d, (string)kv.Value);
                        if (!string.Equals(f, to, StringComparison.OrdinalIgnoreCase)) { if (File.Exists(to)) File.Delete(to); File.Move(f, to); }
                    }
            written.Add(dest + "\\");
        }
        else if (kind == "msi")
        {
            string tmp = Path.Combine(_work, "msi_" + id);
            if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
            // /a = administrative install: unpacks the files, registers nothing, needs no admin rights
            Exec("msiexec.exe", "/a \"" + file + "\" /qn TARGETDIR=\"" + tmp + "\"", 300);
            string hit = Directory.GetFiles(tmp, Str(t, "take"), SearchOption.AllDirectories).FirstOrDefault();
            if (hit == null) throw new BuildFailed(L.T("у ", "") + Path.GetFileName(url) + L.T(" немає ", " has no ") + Str(t, "take"));
            File.Copy(hit, Path.Combine(_bin, Str(t, "take")), true);
            written.Add(Str(t, "take"));
            Directory.Delete(tmp, true);
        }
        else throw new BuildFailed(L.T("невідомий kind ", "unknown kind ") + kind);

        // extra copies some modules expect under another name (Autoruns: autorunsc64.exe in bin root)
        if (t.ContainsKey("copy_to"))
        {
            var ct = t["copy_to"];
            if (ct is object[])
                foreach (object o in (object[])ct) { CopyIn(Str(t, "take"), (string)o); written.Add((string)o); }
            else
                foreach (var kv in (Dictionary<string, object>)ct) { CopyIn(kv.Key, (string)kv.Value); written.Add((string)kv.Value); }
        }

        string check = Str(t, "check");
        if (check != "" && !File.Exists(Path.Combine(_bin, check)))
            throw new BuildFailed(L.T("після розпаковки немає ", "after unpacking there is no ") + check + L.T(" (змінилась структура архіву в ", " (the archive layout changed in ") + url + ")");

        // pinned hashes hold for the pinned release only (pin_tag); a newer release is checked by
        // the author's digest or signature instead, so "always the newest" does not mean "unchecked"
        string pinTag = Str(t, "pin_tag");
        if (t.ContainsKey("sha256") && (pinTag == "" || pinTag == _ver))
        {
            foreach (var kv in (Dictionary<string, object>)t["sha256"])
            {
                string got = Sha256(Path.Combine(_bin, kv.Key));
                if (!string.Equals(got, (string)kv.Value, StringComparison.OrdinalIgnoreCase))
                {
                    File.Delete(Path.Combine(_bin, kv.Key));
                    throw new BuildFailed(kv.Key + L.T(": SHA-256 не збігається із зафіксованим (", ": SHA-256 does not match the pinned value (") + got.Substring(0, 16) + L.T("...), файл відкинуто", "...), file rejected"));
                }
            }
            how.Add(L.T("закріплений SHA-256", "pinned SHA-256"));
        }

        // Authenticode of the tool's main program; "signer" in the manifest makes it mandatory
        string main = check != "" ? check : (written.FirstOrDefault(w => w.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) ?? "");
        string need = Str(t, "signer");
        if (main != "")
        {
            string subj = Authenticode.Signer(Path.Combine(_bin, main));
            if (need != "" && (subj == null || subj.IndexOf(need, StringComparison.OrdinalIgnoreCase) < 0))
                throw new BuildFailed(main + L.T(": немає дійсного підпису ", ": no valid signature of ") + need + (subj == null ? "" : " (" + subj + ")"));
            if (subj != null) how.Add(L.T("підпис ", "signed ") + subj);
        }
        if (how.Count == 0) how.Add(L.T("лише HTTPS (автор не публікує хеш/підпис)", "HTTPS only (the author publishes no hash/signature)"));

        foreach (string w in written)
        {
            _tierOfTop[w.Split('\\')[0].TrimEnd('\\')] = tier;
            Record(id, w, url, _ver, string.Join("; ", how));
        }
    }

    void CopyIn(string fromRel, string toRel)
    {
        string to = Path.Combine(_bin, toRel);
        Directory.CreateDirectory(Path.GetDirectoryName(to));
        File.Copy(Path.Combine(_bin, fromRel), to, true);
    }

    string ResolveUrl(Dictionary<string, object> t)
    {
        string url = Str(t, "url");
        if (url.StartsWith("{mirror}"))
        {
            if (_mirror == "") throw new BuildFailed(L.T("немає адреси дзеркала інструментів (mirror.txt)", "no tools mirror address (mirror.txt)"));
            _ver = "mirror";
            return _mirror + url.Substring(8);
        }
        if (url != "") return url;
        return GitHubAsset(Str(t, "github"), Str(t, "asset"), t.ContainsKey("prerelease"));
    }

    // Newest release of a GitHub repository (pre-releases too when the author ships fixes only
    // that way); sets _ver to its tag and _digest to the sha256 GitHub keeps for every asset.
    string GitHubAsset(string repo, string rx, bool prerelease)
    {
        var js = new JavaScriptSerializer();
        // the last answer per repository is kept: when the API refuses (60 requests/hour without a
        // token) the build goes on with the last known release - its files are still digest-checked
        string api = "https://api.github.com/repos/" + repo + (prerelease ? "/releases?per_page=10" : "/releases/latest");
        string known = Path.Combine(_cache, "gh_" + Regex.Replace(repo, "[^A-Za-z0-9]", "_") + (prerelease ? "_pre" : "") + ".json");
        string json;
        try { json = Http(api); File.WriteAllText(known, json, new UTF8Encoding(false)); }
        catch (BuildFailed e)
        {
            if (!File.Exists(known)) throw;
            _log("   ! " + e.Message);
            _log(L.T("   беру останній відомий реліз ", "   using the last known release of ") + repo + " (" + File.GetLastWriteTime(known).ToString("yyyy-MM-dd HH:mm") + ")");
            json = File.ReadAllText(known);
        }
        Dictionary<string, object> rel;
        if (prerelease)
            rel = ((object[])js.DeserializeObject(json))
                  .Cast<Dictionary<string, object>>().FirstOrDefault(r => !(r["draft"] is bool && (bool)r["draft"]));
        else
            rel = (Dictionary<string, object>)js.DeserializeObject(json);
        if (rel == null) throw new BuildFailed(repo + L.T(": немає релізів", ": no releases"));
        _ver = Str(rel, "tag_name");
        foreach (Dictionary<string, object> a in (object[])rel["assets"])
            if (Regex.IsMatch((string)a["name"], rx))
            {
                string d = Str(a, "digest");
                _digest = d.StartsWith("sha256:") ? d.Substring(7).ToLowerInvariant() : "";
                return (string)a["browser_download_url"];
            }
        throw new BuildFailed(L.T("у релізі ", "release ") + repo + " " + _ver + L.T(" немає файлу ", " has no file ") + rx);
    }

    void SevenZip(Dictionary<string, object> s)
    {
        try { SevenZipFrom(s, false); }
        catch (BuildFailed e)
        {
            if (_mirror == "") throw;
            _log("   ! " + e.Message);
            _log(L.T("   пробую запасне дзеркало для 7-Zip", "   trying the fallback mirror for 7-Zip"));
            SevenZipFrom(s, true);
            _warnings.Add(L.T("7-Zip: офіційне джерело не пройшло (", "7-Zip: the official source failed (") + e.Message + L.T(") - взято з дзеркала", ") - taken from the mirror"));
        }
    }

    void SevenZipFrom(Dictionary<string, object> s, bool fromMirror)
    {
        string zrUrl, exUrl, zrDigest = "", ver;
        var howZr = new List<string>();
        var how = new List<string>();
        if (fromMirror) { zrUrl = _mirror + "/7zr.exe"; exUrl = _mirror + "/7z-extra.7z"; _digest = ""; ver = "mirror"; }
        else if (Str(s, "github") != "")
        {
            // ip7z/7zip is the author's own GitHub: newest release, GitHub's per-asset digest
            zrUrl = GitHubAsset(Str(s, "github"), Str(s, "bootstrap_asset"), false); zrDigest = _digest;
            exUrl = GitHubAsset(Str(s, "github"), Str(s, "extra_asset"), false);
            ver = _ver;
        }
        else { zrUrl = Str(s, "bootstrap"); exUrl = Str(s, "extra"); _digest = ""; ver = ""; }
        string exDigest = _digest;
        _ver = ver; _digest = zrDigest;
        string zr = Fetch("7zr", zrUrl, fromMirror ? "7zr.exe" : null, howZr, false);
        RequirePe(zr, "7zr");
        _ver = ver; _digest = exDigest;
        string extra = Fetch("7z-extra", exUrl, fromMirror ? "7z-extra.7z" : null, how, false);
        if (how.Count == 0) how.Add(L.T("лише HTTPS", "HTTPS only"));
        string tmp = Path.Combine(_work, "7z_extra");
        if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
        Exec(zr, "x -y -o\"" + tmp + "\" \"" + extra + "\"", 120);
        string dest = Path.Combine(_stage, (string)s["dest"]);
        Directory.CreateDirectory(dest);
        foreach (object n in (object[])s["take"])
        {
            string f = Path.Combine(tmp, (string)n);
            if (!File.Exists(f)) throw new BuildFailed(L.T("у 7-Zip Extra немає ", "7-Zip Extra has no ") + n);
            File.Copy(f, Path.Combine(dest, (string)n), true);
            Record("7-Zip", "7za\\" + n, exUrl, _ver, string.Join("; ", how));
        }
        Directory.Delete(tmp, true);
    }

    // ---------------------------------------------------------------- payload

    // Tier rules are build_tiers.py's: everything outside Modules\bin is core; inside it the
    // first path segment decides; a segment no tool claimed is 'extra' and is left out.
    string Classify(string rel)
    {
        string[] p = rel.Split('/');
        if (p.Length < 3 || !p[0].Equals("Modules", StringComparison.OrdinalIgnoreCase) ||
            !p[1].Equals("bin", StringComparison.OrdinalIgnoreCase)) return "core";
        string tier;
        return _tierOfTop.TryGetValue(p[2], out tier) ? tier : "extra";
    }

    int WritePayload(string zipPath)
    {
        var tiers = new Dictionary<string, List<string>> { { "core", new List<string>() }, { "fast", new List<string>() }, { "full", new List<string>() } };
        int extra = 0;
        if (File.Exists(zipPath)) File.Delete(zipPath);
        using (var fs = File.Create(zipPath))
        using (var z = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            foreach (string f in Directory.GetFiles(_stage, "*", SearchOption.AllDirectories))
            {
                string rel = f.Substring(_stage.Length + 1).Replace('\\', '/');
                string tier = Classify(rel);
                if (tier == "extra") { extra++; continue; }
                tiers[tier].Add(rel);
                z.CreateEntryFromFile(f, rel, CompressionLevel.NoCompression);
            }
            var sb = new StringBuilder();
            foreach (string t in new[] { "core", "fast", "full" })
                foreach (string p in tiers[t]) sb.Append(t).Append('\t').Append(p).Append('\n');
            var e = z.CreateEntry("_tiers.txt", CompressionLevel.NoCompression);
            using (var w = new StreamWriter(e.Open(), new UTF8Encoding(false))) w.Write(sb.ToString());
        }
        return extra;
    }

    void Verify(string exe)
    {
        using (var fs = File.OpenRead(exe))
        {
            fs.Seek(-16, SeekOrigin.End);
            var tail = new byte[16];
            fs.Read(tail, 0, 16);
            if (Encoding.ASCII.GetString(tail, 8, 8) != MAGIC) throw new BuildFailed(L.T("немає мітки оверлею", "no overlay marker"));
            long off = BitConverter.ToInt64(tail, 0);
            var buf = new byte[fs.Length - 16 - off];
            fs.Seek(off, SeekOrigin.Begin);
            int got = 0;
            while (got < buf.Length) got += fs.Read(buf, got, buf.Length - got);
            using (var z = new ZipArchive(new MemoryStream(buf), ZipArchiveMode.Read))
            {
                var names = new HashSet<string>(z.Entries.Select(e => e.FullName));
                var miss = REQUIRED.Where(r => !names.Contains(r)).ToList();
                if (miss.Count > 0) throw new BuildFailed(L.T("у збирачі бракує: ", "the collector is missing: ") + string.Join(", ", miss));
                _log(string.Format(L.T("   {0} файлів в оверлеї, обов'язкові на місці", "   {0} files in the overlay, required ones present"), names.Count));
            }
        }
    }

    void WriteProvenance(string path, string kid, string sha)
    {
        File.WriteAllText(path, ProvenanceText(kid, sha), new UTF8Encoding(true));
    }

    string ProvenanceText(string kid, string sha)
    {
        var sb = new StringBuilder();
        sb.AppendLine(L.T("DFIR Collector - походження вмісту / tools provenance", "DFIR Collector - tools provenance"));
        sb.AppendLine(L.T("Зібрано ", "Built ") + DateTime.Now.ToString("yyyy-MM-dd HH:mm") + L.T(" на ", " on ") + Environment.MachineName);
        sb.AppendLine(L.T("Ключ бота (key id): ", "Bot key (key id): ") + kid);
        sb.AppendLine("SHA-256 DFIR_Collector.exe: " + sha);
        sb.AppendLine();
        sb.AppendLine(L.T("Кожен сторонній інструмент завантажено з джерела автора (найновіший випуск); ліцензії - у їхніх теках і на сторінках авторів.", "Every third-party tool was downloaded from its author's source (newest release); licences are in their folders and on the authors' pages."));
        sb.AppendLine(L.T("Колонки: інструмент, файл, SHA-256, версія (тег релізу / дата файлу на сервері / mirror), [чим перевірено], звідки.", "Columns: tool, file, SHA-256, version (release tag / file date on the server / mirror), [how verified], source."));
        sb.AppendLine();
        foreach (string l in _prov) sb.AppendLine(l);
        if (_warnings.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine(L.T("НЕ ЗІБРАНО (крок дасть порожній рядок у collection_gaps.csv):", "NOT BUILT (the step gives an empty row in collection_gaps.csv):"));
            foreach (string w in _warnings) sb.AppendLine("  " + w);
        }
        return sb.ToString();
    }

    void Record(string id, string rel, string source, string ver = "", string how = "")
    {
        string full = Path.Combine(rel.StartsWith("kape") || rel.StartsWith("7za") ? _stage : _bin, rel.TrimEnd('\\'));
        string sha = File.Exists(full) ? Sha256(full) : L.T("(тека)", "(folder)");
        if (ver == "") ver = "-";
        if (how == "") how = L.T("надано користувачем", "supplied by the user");
        _prov.Add(string.Format("{0,-24} {1,-44} {2}  {3,-12} [{4}]  {5}", id, rel, sha, ver, how, source));
        _log("   " + rel + (sha.Length == 64 ? "  sha256 " + sha.Substring(0, 16) : ""));
    }

    // ---------------------------------------------------------------- Defender

    // Runs this same EXE elevated with --add-exclusions (one UAC prompt); the elevated copy adds
    // the folders through WMI MSFT_MpPreference, as the collector core does on a target.
    void AddDefenderExclusions(string[] dirs)
    {
        _log(L.T("== Винятки Defender для ", "== Defender exclusions for ") + string.Join(", ", dirs) + L.T(" (запит прав адміністратора)", " (administrator prompt)"));
        var psi = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,
            "--add-exclusions " + string.Join(" ", dirs.Select(d => "\"" + d.TrimEnd('\\') + "\"")))
        { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
        try
        {
            using (var p = Process.Start(psi))
            {
                p.WaitForExit(120000);
                if (p.ExitCode != 0) _warnings.Add(L.T("Defender: винятки не додано (код ", "Defender: exclusions not added (code ") + p.ExitCode + ")");
            }
        }
        catch (System.ComponentModel.Win32Exception)
        {
            _warnings.Add(L.T("Defender: права адміністратора не надано, винятки не додано", "Defender: administrator rights not granted, exclusions not added"));
        }
    }

    public static int AddExclusionsElevated(string[] dirs)
    {
        int bad = 0;
        foreach (string d in dirs)
        {
            try
            {
                using (var cls = new System.Management.ManagementClass(
                    new System.Management.ManagementScope(@"root\Microsoft\Windows\Defender"),
                    new System.Management.ManagementPath("MSFT_MpPreference"), null))
                {
                    var inp = cls.GetMethodParameters("Add");
                    inp["ExclusionPath"] = new[] { d };
                    cls.InvokeMethod("Add", inp, null);
                }
            }
            catch { bad++; }
        }
        return bad;
    }

    // ---------------------------------------------------------------- helpers

    // Download through a cache that cannot go stale: a URL naming a release tag (or a NuGet version)
    // is immutable; any other URL ("latest", EZ Tools, Sysinternals) is re-checked with HEAD
    // (ETag / Last-Modified / length) and fetched again when the server has a different file.
    // Then the file is verified: the author's GitHub digest, or the mirror's SHA256SUMS.
    string Fetch(string id, string url, string mirrorName, List<string> how, bool pinned)
    {
        string name = id + "_" + Sha256(Encoding.UTF8.GetBytes(url)).Substring(0, 12) + "_" + SafeName(url);
        string dst = Path.Combine(_cache, name), meta = dst + ".meta";
        bool immutable = (_ver != "" && _ver != "mirror" && url.Contains("/releases/download/" + _ver + "/")) || url.Contains("/v3-flatcontainer/");
        bool have = File.Exists(dst) && new FileInfo(dst).Length > 0;
        string stamp = null;
        if (have && !immutable)
        {
            stamp = Head(url);
            if (stamp == GONE)
            {
                // the author removed the file: a fresh machine would get nothing, so say it loudly
                if (_mirror != "" && mirrorName == null) throw new BuildFailed(url + L.T(" більше не існує (404)", " no longer exists (404)"));
                _warnings.Add(id + L.T(": офіційне посилання зникло (404), використано кешовану копію - оновіть tools.json", ": the official link is gone (404), the cached copy was used - update tools.json"));
                _log(L.T("   ! посилання зникло (404) - беру перевірену копію з кешу", "   ! the link is gone (404) - using the verified cached copy"));
            }
            else if (stamp == null) _log(L.T("   сервер не відповів на перевірку - беру з кешу: ", "   the server did not answer the check - using the cache: ") + Path.GetFileName(url));
            else if (File.Exists(meta) && File.ReadAllText(meta) == stamp) _log(L.T("   з кешу (на сервері та сама версія): ", "   from cache (same version on the server): ") + Path.GetFileName(url));
            else { _log(L.T("   на сервері новіша версія: ", "   the server has a newer file: ") + Path.GetFileName(url)); have = false; }
        }
        else if (have) _log(L.T("   з кешу: ", "   from cache: ") + Path.GetFileName(url));
        if (!have)
        {
            _log(L.T("   завантажую ", "   downloading ") + url);
            string tmp = dst + ".part";
            using (var wc = new WebClient())
            {
                wc.Headers.Add("User-Agent", "DFIR-Collector-Builder");
                try { wc.DownloadFile(url, tmp); }
                catch (WebException e) { throw new BuildFailed(L.T("не завантажилось ", "download failed ") + url + ": " + e.Message); }
                stamp = Stamp(wc.ResponseHeaders);
            }
            if (File.Exists(dst)) File.Delete(dst);
            File.Move(tmp, dst);
            if (!immutable) File.WriteAllText(meta, stamp ?? "");
        }
        if (_ver == "" && File.Exists(meta))
        {
            // no release tag: the server's Last-Modified date is the version we can name
            string[] p = File.ReadAllText(meta).Split('|');
            DateTime lm;
            if (p.Length > 1 && DateTime.TryParse(p[1], out lm)) _ver = lm.ToUniversalTime().ToString("yyyy-MM-dd");
        }

        string got = Sha256(dst);
        if (mirrorName != null)
        {
            string want = MirrorSum(mirrorName);
            if (want == null && !pinned) throw new BuildFailed(L.T("дзеркало не публікує SHA256SUMS для ", "the mirror publishes no SHA256SUMS for ") + mirrorName);
            if (want != null)
            {
                if (got != want) { File.Delete(dst); throw new BuildFailed(mirrorName + L.T(": SHA-256 не збігається з SHA256SUMS дзеркала, файл відкинуто", ": SHA-256 does not match the mirror's SHA256SUMS, file rejected")); }
                how.Add(L.T("SHA256SUMS дзеркала", "mirror SHA256SUMS"));
            }
        }
        else if (_digest != "")
        {
            if (got != _digest) { File.Delete(dst); throw new BuildFailed(Path.GetFileName(url) + L.T(": SHA-256 не збігається з контрольною сумою автора на GitHub, файл відкинуто", ": SHA-256 does not match the author's digest on GitHub, file rejected")); }
            how.Add(L.T("дайджест GitHub", "GitHub digest"));
        }
        return dst;
    }

    Dictionary<string, string> LoadMirrorSums()
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using (var wc = new WebClient())
            {
                wc.Headers.Add("User-Agent", "DFIR-Collector-Builder");
                foreach (string line in wc.DownloadString(_mirror + "/SHA256SUMS").Split('\n'))
                {
                    var m = Regex.Match(line.Trim(), @"^([0-9a-fA-F]{64})\s+\*?(.+)$");
                    if (m.Success) d[m.Groups[2].Value.Trim()] = m.Groups[1].Value.ToLowerInvariant();
                }
            }
        }
        catch (WebException) { }
        return d;
    }

    string MirrorSum(string name)
    {
        if (_mirrorSums == null) _mirrorSums = LoadMirrorSums();
        string v;
        return _mirrorSums.TryGetValue(name, out v) ? v : null;
    }

    const string GONE = "(gone)";

    static string Stamp(WebHeaderCollection h)
    {
        if (h == null) return null;
        return (h["ETag"] ?? "") + "|" + (h["Last-Modified"] ?? "") + "|" + (h["Content-Length"] ?? "");
    }

    static string Head(string url)
    {
        try
        {
            var r = (HttpWebRequest)WebRequest.Create(url);
            r.Method = "HEAD";
            r.UserAgent = "DFIR-Collector-Builder";
            r.Timeout = 30000;
            using (var resp = (HttpWebResponse)r.GetResponse()) return Stamp(resp.Headers);
        }
        catch (WebException e)
        {
            var hr = e.Response as HttpWebResponse;
            return hr != null && (hr.StatusCode == HttpStatusCode.NotFound || hr.StatusCode == HttpStatusCode.Gone) ? GONE : null;
        }
    }

    static string SafeName(string url)
    {
        string n = url.Split('?')[0];
        n = n.Substring(n.LastIndexOf('/') + 1);
        return Regex.Replace(n, @"[^A-Za-z0-9._+-]", "_");
    }

    static string Http(string url)
    {
        using (var wc = new WebClient())
        {
            wc.Headers.Add("User-Agent", "DFIR-Collector-Builder");
            string tok = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
            if (!string.IsNullOrEmpty(tok) && url.StartsWith("https://api.github.com/")) wc.Headers.Add("Authorization", "Bearer " + tok);
            wc.Encoding = Encoding.UTF8;
            try { return wc.DownloadString(url); }
            catch (WebException e) { throw new BuildFailed(L.T("GitHub не відповів (", "GitHub did not answer (") + e.Message + L.T("); спробуйте за годину: ліміт 60 запитів/год", "); try again in an hour: limit 60 requests/hour")); }
        }
    }

    // A single top-level folder in the archive (repo-master/, chainsaw/) is dropped so the
    // module paths (regripper\rip.exe, Chainsaw\Chainsaw.exe) line up.
    static void ExtractZip(Stream s, string dest, bool stripSingleTop)
    {
        ExtractZip(s, dest, stripSingleTop, new string[0]);
    }

    // drop: paths relative to dest (a folder drops everything under it) or file-name patterns with *
    static void ExtractZip(Stream s, string dest, bool stripSingleTop, string[] drop)
    {
        var dropDirs = drop.Where(x => !x.Contains("*")).Select(x => x.Replace('\\', '/').TrimEnd('/') + "/").ToList();
        var dropNames = drop.Where(x => x.Contains("*"))
            .Select(x => new Regex("^" + Regex.Escape(x).Replace(@"\*", ".*") + "$", RegexOptions.IgnoreCase)).ToList();
        using (var z = new ZipArchive(s, ZipArchiveMode.Read))
        {
            string strip = "";
            if (stripSingleTop)
            {
                var tops = z.Entries.Where(e => e.FullName.Length > 0)
                    .Select(e => e.FullName.Replace('\\', '/').Split('/')[0]).Distinct().ToList();
                bool allInDir = z.Entries.All(e => e.FullName.Replace('\\', '/').Contains("/"));
                if (tops.Count == 1 && allInDir) strip = tops[0] + "/";
            }
            string root = Path.GetFullPath(dest);
            foreach (var e in z.Entries)
            {
                string n = e.FullName.Replace('\\', '/');
                if (strip != "" && n.StartsWith(strip)) n = n.Substring(strip.Length);
                if (n == "") continue;
                if (dropDirs.Any(x => (n + "/").StartsWith(x, StringComparison.OrdinalIgnoreCase)) ||
                    dropNames.Any(r => r.IsMatch(n.TrimEnd('/').Split('/').Last()))) continue;
                string target = Path.GetFullPath(Path.Combine(root, n));
                if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase)) continue;   // zip-slip
                if (n.EndsWith("/")) { Directory.CreateDirectory(target); continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                e.ExtractToFile(target, true);
            }
        }
    }

    // take: an exact path inside the archive, or a file-name pattern (* allowed) matched on the last segment
    static void TakeFromZip(string zipFile, string take, string dst)
    {
        using (var z = ZipFile.OpenRead(zipFile))
        {
            string want = take.Replace('\\', '/');
            var rx = new Regex("^" + Regex.Escape(Path.GetFileName(want)).Replace(@"\*", ".*") + "$", RegexOptions.IgnoreCase);
            var hit = z.Entries.FirstOrDefault(e => e.FullName.Equals(want, StringComparison.OrdinalIgnoreCase))
                   ?? z.Entries.Where(e => rx.IsMatch(e.Name)).OrderBy(e => e.FullName.Length).FirstOrDefault();
            if (hit == null) throw new BuildFailed(L.T("у ", "") + Path.GetFileName(zipFile) + L.T(" немає ", " has no ") + take);
            Directory.CreateDirectory(Path.GetDirectoryName(dst));
            hit.ExtractToFile(dst, true);
        }
    }

    static void CopyTree(string from, string to)
    {
        foreach (string f in Directory.GetFiles(from, "*", SearchOption.AllDirectories))
        {
            string t = Path.Combine(to, f.Substring(from.Length + 1));
            Directory.CreateDirectory(Path.GetDirectoryName(t));
            File.Copy(f, t, true);
        }
    }

    static void RequirePe(string f, string id)
    {
        var b = new byte[2];
        using (var fs = File.OpenRead(f)) fs.Read(b, 0, 2);
        if (b[0] != 'M' || b[1] != 'Z') throw new BuildFailed(id + L.T(": завантажено не програму (можливо, сторінка помилки)", ": the download is not a program (maybe an error page)"));
    }

    static string FindCsc()
    {
        string w = Environment.GetEnvironmentVariable("WINDIR") ?? @"C:\Windows";
        foreach (string fw in new[] { "Framework64", "Framework" })
        {
            string p = Path.Combine(w, "Microsoft.NET", fw, "v4.0.30319", "csc.exe");
            if (File.Exists(p)) return p;
        }
        throw new BuildFailed(L.T("Не знайдено csc.exe (.NET Framework 4). Увімкніть .NET Framework 4.8 у «Компонентах Windows».", "csc.exe not found (.NET Framework 4). Turn on .NET Framework 4.8 in «Windows Features»."));
    }

    void Csc(string csc, string[] args)
    {
        string a = "/nologo " + string.Join(" ", args.Select(x => x.Contains(" ") ? "\"" + x + "\"" : x));
        string outp = Exec(csc, a, 300);
        if (outp.Contains(" error ")) throw new BuildFailed(L.T("помилка компіляції:\r\n", "compile error:\r\n") + outp);
    }

    static string Exec(string exe, string args, int timeoutSec)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        using (var p = Process.Start(psi))
        {
            var so = p.StandardOutput.ReadToEndAsync();
            var se = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutSec * 1000)) { try { p.Kill(); } catch { } throw new BuildFailed(Path.GetFileName(exe) + L.T(" не завершився за ", " did not finish within ") + timeoutSec + L.T(" с", " s")); }
            string all = so.Result + se.Result;
            if (p.ExitCode != 0) throw new BuildFailed(Path.GetFileName(exe) + L.T(" код ", " code ") + p.ExitCode + ": " + all.Trim());
            return all;
        }
    }

    static string Str(Dictionary<string, object> d, string k)
    {
        object v;
        return d.TryGetValue(k, out v) && v != null ? v.ToString() : "";
    }

    static Stream ResourceStream(string name)
    {
        var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
        if (s == null) throw new BuildFailed(L.T("у конструкторі немає вбудованого ", "the builder has no embedded ") + name + L.T(" (зібраний не через make_builder.ps1?)", " (not built with make_builder.ps1?)"));
        return s;
    }

    static string ResourceText(string name)
    {
        using (var r = new StreamReader(ResourceStream(name), Encoding.UTF8)) return r.ReadToEnd();
    }

    static string Sha256(string file)
    {
        using (var h = SHA256.Create())
        using (var fs = File.OpenRead(file))
            return BitConverter.ToString(h.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
    }

    static string Sha256(byte[] data)
    {
        using (var h = SHA256.Create()) return BitConverter.ToString(h.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
    }
}


// Authenticode check through WinVerifyTrust (what Explorer's "Digital signatures" tab checks):
// the signer's CN when the signature is valid, null when unsigned or broken. Revocation is not
// checked online - the builder has to work behind a proxy.
static class Authenticode
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct TrustFile { public uint cbStruct; public string path; public IntPtr hFile; public IntPtr known; }

    [StructLayout(LayoutKind.Sequential)]
    struct TrustData
    {
        public uint cbStruct; public IntPtr policy; public IntPtr sip; public uint ui; public uint revocation;
        public uint unionChoice; public IntPtr file; public uint stateAction; public IntPtr state;
        public IntPtr url; public uint provFlags; public uint uiContext; public IntPtr sigSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    static extern int WinVerifyTrust(IntPtr hwnd, [In] ref Guid action, ref TrustData data);

    public static string Signer(string path)
    {
        var fi = new TrustFile { cbStruct = (uint)Marshal.SizeOf(typeof(TrustFile)), path = path };
        IntPtr pfi = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TrustFile)));
        try
        {
            Marshal.StructureToPtr(fi, pfi, false);
            var td = new TrustData
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(TrustData)), ui = 2 /* none */, revocation = 0,
                unionChoice = 1 /* file */, file = pfi, provFlags = 0x10 /* no revocation */ | 0x1000 /* cache only */
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");   // WINTRUST_ACTION_GENERIC_VERIFY_V2
            if (WinVerifyTrust(IntPtr.Zero, ref action, ref td) != 0) return null;
            var m = Regex.Match(X509Certificate.CreateFromSignedFile(path).Subject, @"CN=(""[^""]+""|[^,]+)");
            return m.Success ? m.Groups[1].Value.Trim('"') : "?";
        }
        catch (Exception) { return null; }
        finally { Marshal.DestroyStructure(pfi, typeof(TrustFile)); Marshal.FreeHGlobal(pfi); }
    }
}


// Interface language of the builder (and the default language of the collector it builds).
static class L
{
    public static bool En = true;
    public static string Code { get { return En ? "en" : "uk"; } }
    public static string T(string uk, string en) { return En ? en : uk; }
    public static void FromSystem()
    {
        string c = System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
        En = !(c == "uk" || c == "ru");
    }
}
