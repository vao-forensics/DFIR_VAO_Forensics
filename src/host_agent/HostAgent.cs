// DFIR VAO Host Agent: the AI side of the Windows host the DFIR VM runs on.
//
//   * sees the NVIDIA GPUs (nvidia-smi) and picks the model profile the Linux installer would pick
//   * installs the newest llama.cpp CUDA build and llama-swap from their GitHub releases (SHA-256 from
//     the release metadata is checked, every file goes to provenance.jsonl) and the GGUF models of the
//     profile from Hugging Face (SHA-256 of the LFS object checked)
//   * serves ONE port for the VM: a small reverse proxy in front of llama-swap (which listens on
//     127.0.0.1 only) that wants the agent token, queues inference requests (max N at a time) and
//     answers /agent/hello (no secret, lets the VM find the agent) and /agent/status (token)
//   * autostart (admin: SYSTEM task at boot; otherwise: HKCU Run at logon), firewall rule limited to
//     the virtual-adapter subnets (admin only), update with a trial run and rollback
//
// No arguments = window (AgentForm.cs). CLI for scripts and tests:
//   --detect | --plan | --gen-config OUT | --install [--no-models] | --serve | --status | --hello
//   --check-update | --update [--from-zip LLAMA_ZIP] | --autostart on|off | --token show|new
// Options: --home DIR  --port N  --swap-port N  --profile auto|tiny|small|medium|large
//          --fake-gpus 16,16  --parallel N  --lang en|uk  --task-name NAME
// Build: src\host_agent\make_agent.ps1 (.NET Framework csc, C# 5).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace DfirVao
{
    public class Gpu
    {
        public int Index; public string Name; public int TotalMb; public int UsedMb; public int Util;
        public int GB { get { return TotalMb / 1024; } }
    }

    public class Settings
    {
        public int Port = 1234;
        public int SwapPort = 1235;
        public string Token = "";
        public string Profile = "auto";
        public string ModelsDir = "";
        public int Parallel = 4;
        public string LlamaTag = "";
        public string SwapTag = "";
        public string TaskName = "DFIR-VAO-Agent";
    }

    public static partial class Agent
    {
        public const string Version = "1.0";
        public static string Home = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DFIR_VAO_Agent");
        public static Settings S = new Settings();
        public static bool Uk = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "uk";
        public static string FakeGpus = "";
        public static Action<string> Log = delegate(string m) { Console.WriteLine(m); };
        static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };

        public static string T(string uk, string en) { return Uk ? uk : en; }

        // ------------------------------------------------------------------ settings
        static string SettingsPath { get { return Path.Combine(Home, "agent.json"); } }
        public static void LoadSettings()
        {
            if (File.Exists(SettingsPath))
                try { S = Json.Deserialize<Settings>(File.ReadAllText(SettingsPath)) ?? new Settings(); }
                catch (Exception e) { throw new Exception(T("пошкоджений ", "damaged ") + SettingsPath + ": " + e.Message); }
            if (string.IsNullOrEmpty(S.ModelsDir)) S.ModelsDir = Path.Combine(Home, "models");
        }
        public static void SaveSettings()
        {
            Directory.CreateDirectory(Home);
            File.WriteAllText(SettingsPath, Json.Serialize(S), new UTF8Encoding(false));
        }
        public static string NewToken()
        {
            var b = new byte[24];
            using (var r = RandomNumberGenerator.Create()) r.GetBytes(b);
            return "vao_" + BitConverter.ToString(b).Replace("-", "").ToLowerInvariant();
        }

        // ------------------------------------------------------------------ processes
        public static int Run(string exe, string args, out string output, int timeoutMs)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
                CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8
            };
            var sb = new StringBuilder();
            try
            {
                using (var p = Process.Start(psi))
                {
                    p.OutputDataReceived += delegate(object s, DataReceivedEventArgs e) { if (e.Data != null) lock (sb) sb.AppendLine(e.Data); };
                    p.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e) { if (e.Data != null) lock (sb) sb.AppendLine(e.Data); };
                    p.BeginOutputReadLine(); p.BeginErrorReadLine();
                    if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch { } output = sb.ToString(); return -2; }
                    p.WaitForExit();
                    output = sb.ToString(); return p.ExitCode;
                }
            }
            catch (Exception e) { output = e.Message; return -1; }
        }
        public static bool IsAdmin()
        {
            var p = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent());
            return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }

        // ------------------------------------------------------------------ GPUs + profile
        public static List<Gpu> Gpus()
        {
            var l = new List<Gpu>();
            if (!string.IsNullOrEmpty(FakeGpus))
            {
                int i = 0;
                foreach (var g in FakeGpus.Split(','))
                    l.Add(new Gpu { Index = i++, Name = "fake", TotalMb = int.Parse(g.Trim()) * 1024 });
                return l;
            }
            string o;
            if (Run("nvidia-smi", "--query-gpu=index,name,memory.total,memory.used,utilization.gpu --format=csv,noheader,nounits", out o, 20000) != 0)
                return l;
            foreach (var line in o.Split('\n'))
            {
                var p = line.Split(',').Select(x => x.Trim()).ToArray();
                if (p.Length < 5) continue;
                int idx, tot, used, ut;
                if (!int.TryParse(p[0], out idx) || !int.TryParse(p[2], out tot)) continue;
                int.TryParse(p[3], out used); int.TryParse(p[4], out ut);
                l.Add(new Gpu { Index = idx, Name = p[1], TotalMb = tot, UsedMb = used, Util = ut });
            }
            return l;
        }

        // Same thresholds as installer/detect_hw.sh and infra/host/setup_llm_host.ps1.
        public static string PickProfile(List<Gpu> g, string want, out string why)
        {
            why = "";
            int n = g.Count, min = n > 0 ? g.Min(x => x.GB) : 0, tot = g.Sum(x => x.GB);
            if (want == "tiny") return "tiny";
            if (want == "auto")
            {
                if (n == 0 || min < 12) { why = T("замало відеопам'яті (найменша карта " + min + " ГБ, потрібно від 12)", "not enough video memory (smallest card " + min + " GB, 12 needed)"); return ""; }
                if (tot >= 80) return "large";
                if (tot >= 40 && n >= 2) return "medium";
                return "small";
            }
            if (want != "small" && n < 2) { why = T("профіль " + want + " потребує 2+ карти", "profile " + want + " needs 2+ cards"); return ""; }
            return want;
        }

        public class ModelFile { public string File, Repo, Path; public double GB; }
        public static readonly Dictionary<string, ModelFile> Catalog = new Dictionary<string, ModelFile>
        {
            { "F20", new ModelFile { File = "gpt-oss-20b-MXFP4.gguf", Repo = "ggml-org/gpt-oss-20b-GGUF", Path = "gpt-oss-20b-MXFP4.gguf", GB = 12.1 } },
            { "G31", new ModelFile { File = "gemma-4-31B-it-Q4_K_S.gguf", Repo = "unsloth/gemma-4-31B-it-GGUF", Path = "gemma-4-31B-it-Q4_K_S.gguf", GB = 17.5 } },
            { "B120", new ModelFile { File = "gpt-oss-120b-MXFP4.gguf", Repo = "ggml-org/gpt-oss-120b-GGUF", Path = "gpt-oss-120b-MXFP4.gguf", GB = 63.4 } },
            // test profile only: 145 MB, runs on the CPU
            { "TINY", new ModelFile { File = "SmolLM2-135M-Instruct-Q8_0.gguf", Repo = "bartowski/SmolLM2-135M-Instruct-GGUF", Path = "SmolLM2-135M-Instruct-Q8_0.gguf", GB = 0.14 } },
        };
        public static string[] ModelsFor(string profile)
        {
            switch (profile)
            {
                case "tiny": return new[] { "TINY" };
                case "small": return new[] { "F20" };
                case "medium": return new[] { "F20", "G31" };
                case "large": return new[] { "F20", "G31", "B120" };
            }
            return new string[0];
        }

        // ------------------------------------------------------------------ config.yaml
        // Keep in step with installer/gen_llm_stack.py and infra/host/setup_llm_host.ps1 (test_host_agent
        // compares the two outputs line by line).
        static readonly string[] CHAT = { "fast", "gpt-oss-20b-heretic", "translate-9b", "gemma-2-9b-translate", "agent-cli" };
        static readonly string[] REA = { "reasoner-31b-b", "agent-30b" };
        static readonly string[] BIG = { "big", "gpt-oss-120b", "agent-big", "smart", "forensic-xl" };

        public static string ServerExe { get { return Path.Combine(Home, "llama", "current", "llama-server.exe"); } }

        static List<string> Model(string name, string gguf, int[] cards, IEnumerable<string> aliases, int ttl, bool cpu)
        {
            string split = cards.Length == 1 ? "--split-mode none --main-gpu 0" : "--split-mode layer --tensor-split " + string.Join(",", cards.Select(c => "1"));
            var l = new List<string> { "  \"" + name + "\":", "    cmd: |",
                "      \"" + ServerExe + "\"", "      -m \"" + Path.Combine(S.ModelsDir, gguf) + "\"", "      --host 127.0.0.1 --port ${PORT}" };
            if (cpu) l.Add("      -ngl 0 -c 4096");
            else l.AddRange(new[] { "      -ngl 99 " + split, "      -fa auto --jinja", "      -c 65536 --cache-type-k q8_0 --cache-type-v q8_0" });
            l.AddRange(new[] { "      --no-webui", "    proxy: \"http://127.0.0.1:${PORT}\"", "    env:",
                "      - \"CUDA_VISIBLE_DEVICES=" + (cpu ? "" : string.Join(",", cards)) + "\"", "    aliases:" });
            l.AddRange(aliases.Select(a => "      - \"" + a + "\""));
            l.Add("    ttl: " + ttl); l.Add("");
            return l;
        }

        public static string GenConfig(List<Gpu> gpus, string profile)
        {
            int n = gpus.Count, min = n > 0 ? gpus.Min(x => x.GB) : 0;
            var head = new List<string> { "# GENERATED by DFIR VAO Host Agent " + Version + " for profile " + profile + " (" + n + " GPU, smallest " + min + " GB).",
                "healthCheckTimeout: 900", "startPort: 5840", "logLevel: info", "", "models:" };
            var body = new List<string>(); var tail = new List<string>();
            string F20 = Catalog["F20"].File, G31 = Catalog["G31"].File, B120 = Catalog["B120"].File;
            var everything = CHAT.Concat(new[] { "reasoner-31b" }).Concat(REA).Concat(new[] { "big-120b" }).Concat(BIG);
            if (profile == "tiny")
                body = Model("gpt-small-20b", Catalog["TINY"].File, new[] { 0 }, everything, 600, true);
            else if (profile == "small")
                body = Model("gpt-small-20b", F20, new[] { 0 }, everything, 86400, false);
            else
            {
                var all = Enumerable.Range(0, n).ToArray();
                var rest = Enumerable.Range(1, n - 1).ToArray();
                int[] rg = min >= 26 ? new[] { rest[0] } : rest.Length >= 2 ? new[] { rest[0], rest[1] } : rest;
                var bigAlias = profile == "large" ? new string[0] : new[] { "big-120b" }.Concat(BIG).ToArray();
                if (rg.Length * min < 26)
                    body = Model("reasoner-31b", G31, all, new[] { "gpt-small-20b" }.Concat(CHAT).Concat(REA).Concat(bigAlias), 86400, false);
                else
                {
                    body = Model("gpt-small-20b", F20, new[] { 0 }, CHAT, 86400, false);
                    body.AddRange(Model("reasoner-31b", G31, rg, REA.Concat(bigAlias), 86400, false));
                    tail.AddRange(new[] { "matrix:", "  vars:", "    chat: \"gpt-small-20b\"", "    rea: \"reasoner-31b\"" });
                    if (profile == "large")
                    {
                        body.AddRange(Model("big-120b", B120, all, BIG, 900, false));
                        tail.AddRange(new[] { "    big: \"big-120b\"", "  sets:", "    main: \"chat & rea\"", "    bigset: \"big\"" });
                    }
                    else tail.AddRange(new[] { "  sets:", "    main: \"chat & rea\"" });
                }
            }
            return string.Join("\n", head.Concat(body).Concat(tail)) + "\n";
        }

        // ------------------------------------------------------------------ downloads + provenance
        public static string Http(string url, int timeoutMs)
        {
            var r = (HttpWebRequest)WebRequest.Create(url);
            r.UserAgent = "dfir-vao-host-agent/" + Version; r.Timeout = timeoutMs;
            using (var resp = r.GetResponse()) using (var sr = new StreamReader(resp.GetResponseStream())) return sr.ReadToEnd();
        }
        public static string Sha256(string file)
        {
            using (var f = File.OpenRead(file)) using (var h = SHA256.Create())
                return BitConverter.ToString(h.ComputeHash(f)).Replace("-", "").ToLowerInvariant();
        }
        static void Provenance(string what, string url, string sha, string version)
        {
            var d = new Dictionary<string, object> { { "time", DateTime.UtcNow.ToString("s") + "Z" }, { "what", what }, { "version", version },
                { "url", url }, { "sha256", sha }, { "agent", Version } };
            File.AppendAllText(Path.Combine(Home, "provenance.jsonl"), Json.Serialize(d) + "\n");
        }
        // curl.exe (Windows 10 1803+) resumes and follows redirects; the hash decides, not the size
        public static void Fetch(string url, string dst, string sha, string what, string version)
        {
            if (File.Exists(dst) && !string.IsNullOrEmpty(sha) && Sha256(dst) == sha) { Log(T("вже є: ", "already here: ") + Path.GetFileName(dst)); return; }
            Log(T("завантажую ", "downloading ") + Path.GetFileName(dst));
            string o;
            int rc = Run("curl.exe", "-fsSL --retry 3 -C - -o \"" + dst + ".part\" \"" + url + "\"", out o, 6 * 3600 * 1000);
            if (rc != 0) throw new Exception(T("не вдалося завантажити ", "download failed: ") + url + " " + o.Trim());
            string got = Sha256(dst + ".part");
            if (!string.IsNullOrEmpty(sha) && got != sha)
            {
                File.Delete(dst + ".part");
                throw new Exception(T("SHA-256 не збігається для ", "SHA-256 mismatch for ") + Path.GetFileName(dst) + ": " + got + " != " + sha);
            }
            if (File.Exists(dst)) File.Delete(dst);
            File.Move(dst + ".part", dst);
            Provenance(what, url, got, version);
            Log("  sha256 " + got + (string.IsNullOrEmpty(sha) ? T(" (джерело не дає хешу)", " (source publishes no hash)") : " OK"));
        }

        public class Asset { public string Name, Url, Sha, Tag; }
        // /releases/latest of llama.cpp is not always the newest build (a "v0.9.0" release once sat there):
        // take the highest bNNNN that has both CUDA-12.4 x64 archives.
        public static Asset[] LatestLlama()
        {
            var rels = Json.Deserialize<List<Dictionary<string, object>>>(Http("https://api.github.com/repos/ggml-org/llama.cpp/releases?per_page=20", 30000));
            foreach (var r in rels.Where(x => Regex.IsMatch((string)x["tag_name"], @"^b\d+$")).OrderByDescending(x => int.Parse(((string)x["tag_name"]).Substring(1))))
            {
                Asset bin = null, rt = null;
                foreach (Dictionary<string, object> a in (System.Collections.ArrayList)r["assets"])
                {
                    var name = (string)a["name"];
                    var asset = new Asset { Name = name, Url = (string)a["browser_download_url"], Tag = (string)r["tag_name"],
                        Sha = a.ContainsKey("digest") && a["digest"] != null ? ((string)a["digest"]).Replace("sha256:", "") : "" };
                    if (Regex.IsMatch(name, @"^llama-b\d+-bin-win-cuda-12\.4-x64\.zip$")) bin = asset;
                    if (name == "cudart-llama-bin-win-cuda-12.4-x64.zip") rt = asset;
                }
                if (bin != null && rt != null) return new[] { bin, rt };
            }
            throw new Exception(T("у релізах llama.cpp немає збірки CUDA 12.4 для Windows", "no Windows CUDA 12.4 build in the llama.cpp releases"));
        }
        public static Asset LatestSwap()
        {
            var r = Json.Deserialize<Dictionary<string, object>>(Http("https://api.github.com/repos/mostlygeek/llama-swap/releases/latest", 30000));
            foreach (Dictionary<string, object> a in (System.Collections.ArrayList)r["assets"])
            {
                var name = (string)a["name"];
                if (Regex.IsMatch(name, @"windows_amd64\.zip$"))
                    return new Asset { Name = name, Url = (string)a["browser_download_url"], Tag = (string)r["tag_name"],
                        Sha = a.ContainsKey("digest") && a["digest"] != null ? ((string)a["digest"]).Replace("sha256:", "") : "" };
            }
            throw new Exception("llama-swap: no windows_amd64.zip");
        }
        // Hugging Face keeps the SHA-256 of every LFS file in the tree listing
        public static string HfSha(string repo, string path)
        {
            var l = Json.Deserialize<List<Dictionary<string, object>>>(Http("https://huggingface.co/api/models/" + repo + "/tree/main", 30000));
            foreach (var e in l)
                if ((string)e["path"] == path && e.ContainsKey("lfs")) return (string)((Dictionary<string, object>)e["lfs"])["oid"];
            return "";
        }

        static void Unzip(string zip, string dir)
        {
            Directory.CreateDirectory(dir);
            using (var z = System.IO.Compression.ZipFile.OpenRead(zip))
                foreach (var e in z.Entries)
                {
                    var dst = Path.GetFullPath(Path.Combine(dir, e.FullName));
                    if (!dst.StartsWith(Path.GetFullPath(dir) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) continue;  // no ../
                    if (e.FullName.EndsWith("/")) { Directory.CreateDirectory(dst); continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(dst));
                    using (var s = e.Open()) using (var f = File.Create(dst)) s.CopyTo(f);
                }
        }

        // ------------------------------------------------------------------ llama.cpp builds (junction "current")
        static string LlamaDir { get { return Path.Combine(Home, "llama"); } }
        public static string CurrentTag()
        {
            var cur = Path.Combine(LlamaDir, "current");
            if (!Directory.Exists(cur)) return "";
            var t = Path.Combine(cur, "TAG.txt");
            return File.Exists(t) ? File.ReadAllText(t).Trim() : "";
        }
        static void PointCurrent(string tag)
        {
            var cur = Path.Combine(LlamaDir, "current");
            if (Directory.Exists(cur)) Directory.Delete(cur, false);  // a junction: removes the link, not the build
            string o;
            if (Run("cmd.exe", "/c mklink /J \"" + cur + "\" \"" + Path.Combine(LlamaDir, tag) + "\"", out o, 15000) != 0)
                throw new Exception("mklink: " + o);
        }
        // the trial run: the new llama-server must start and print its version
        static bool TrialRun(string dir, out string why)
        {
            var exe = Path.Combine(dir, "llama-server.exe");
            if (!File.Exists(exe)) { why = T("немає llama-server.exe", "no llama-server.exe"); return false; }
            string o;
            int rc = Run(exe, "--version", out o, 60000);
            why = o.Trim().Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0).LastOrDefault() ?? "";
            if (rc != 0) { why = "exit " + rc + ": " + why; return false; }
            return true;
        }
        // installs a llama.cpp build into llama\<tag>, tries it, then points "current" at it; old builds stay
        public static string InstallLlama(string fromZip)
        {
            Directory.CreateDirectory(LlamaDir);
            var dl = Path.Combine(Home, "dl"); Directory.CreateDirectory(dl);
            string tag; var dir = "";
            if (!string.IsNullOrEmpty(fromZip))
            {
                tag = "local-" + Sha256(fromZip).Substring(0, 12);
                if (tag == CurrentTag()) return tag;
                dir = Path.Combine(LlamaDir, tag);
                if (Directory.Exists(dir)) Directory.Delete(dir, true);
                Unzip(fromZip, dir);
                Provenance("llama.cpp (local zip)", fromZip, Sha256(fromZip), tag);
            }
            else
            {
                var a = LatestLlama(); tag = a[0].Tag;
                dir = Path.Combine(LlamaDir, tag);
                if (!(Directory.Exists(dir) && File.Exists(Path.Combine(dir, "llama-server.exe"))))
                {
                    var tmp = dir + ".new"; if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
                    foreach (var x in a)
                    {
                        var z = Path.Combine(dl, x.Name);
                        Fetch(x.Url, z, x.Sha, "llama.cpp " + x.Name, x.Tag);
                        Unzip(z, tmp);
                    }
                    if (Directory.Exists(dir)) Directory.Delete(dir, true);
                    Directory.Move(tmp, dir);
                }
            }
            File.WriteAllText(Path.Combine(dir, "TAG.txt"), tag);
            string why;
            if (!TrialRun(dir, out why))
            {
                if (tag != CurrentTag()) Directory.Delete(dir, true);
                throw new Exception(T("нова збірка llama.cpp не пройшла пробний запуск (" + why + "): лишаю попередню " + CurrentTag(),
                    "the new llama.cpp build failed its trial run (" + why + "): keeping " + CurrentTag()));
            }
            Log("llama.cpp " + tag + ": " + why);
            PointCurrent(tag);
            S.LlamaTag = tag; SaveSettings();
            return tag;
        }
        // keep only the named builds (the current one and the one to roll back to); never by date: a
        // build that failed and was rolled back is newer than the good one
        static void Prune(params string[] keep)
        {
            foreach (var d in Directory.GetDirectories(LlamaDir))
            {
                var n = Path.GetFileName(d);
                if (n == "current" || keep.Contains(n)) continue;
                try { Directory.Delete(d, true); } catch { }
            }
        }
        public static void InstallSwap()
        {
            var a = LatestSwap();
            var dl = Path.Combine(Home, "dl"); Directory.CreateDirectory(dl);
            var z = Path.Combine(dl, a.Name);
            Fetch(a.Url, z, a.Sha, "llama-swap " + a.Name, a.Tag);
            var dir = Path.Combine(Home, "swap");
            if (Directory.Exists(dir)) try { Directory.Delete(dir, true); } catch { }
            Unzip(z, dir);
            S.SwapTag = a.Tag; SaveSettings();
            Log("llama-swap " + a.Tag);
        }

        // ------------------------------------------------------------------ install
        public static void Install(bool models)
        {
            Directory.CreateDirectory(Home);
            var gpus = Gpus();
            foreach (var g in gpus) Log(string.Format("GPU {0}: {1}, {2} GB", g.Index, g.Name, g.GB));
            string why; var profile = PickProfile(gpus, S.Profile, out why);
            if (profile == "") throw new Exception(why);
            Log(T("Профіль: ", "Profile: ") + profile);
            if (string.IsNullOrEmpty(S.Token)) S.Token = NewToken();
            SaveSettings();
            if (IsAdmin()) Lockdown();
            InstallSwap();
            var prev = CurrentTag();
            var now = InstallLlama(null);
            Prune(now, prev);
            Directory.CreateDirectory(S.ModelsDir);
            if (models)
                foreach (var k in ModelsFor(profile))
                {
                    var m = Catalog[k];
                    Fetch("https://huggingface.co/" + m.Repo + "/resolve/main/" + m.Path, Path.Combine(S.ModelsDir, m.File), HfSha(m.Repo, m.Path), "model " + m.File, m.Repo);
                }
            WriteConfig(profile, gpus);
            if (IsAdmin()) Firewall(true);
            else Log(T("! без прав адміністратора: правило брандмауера не створено", "! not administrator: no firewall rule created"));
        }
        public static void WriteConfig(string profile, List<Gpu> gpus)
        {
            var cfg = Path.Combine(Home, "config.yaml");
            File.WriteAllText(cfg, GenConfig(gpus, profile), new UTF8Encoding(false));
            S.Profile = profile; SaveSettings();
            Log("config.yaml: " + cfg);
        }
        // agent.json holds the token: administrators, SYSTEM and the installing user only
        static void Lockdown()
        {
            string o;
            Run("icacls.exe", "\"" + Home + "\" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F \"" + Environment.UserName + "\":(OI)(CI)F", out o, 30000);
        }

        // ------------------------------------------------------------------ firewall + autostart
        public static List<string> VmSubnets()
        {
            var l = new List<string>();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!Regex.IsMatch(ni.Name + " " + ni.Description, "VMnet|vEthernet|VirtualBox|Hyper-V", RegexOptions.IgnoreCase)) continue;
                foreach (var u in ni.GetIPProperties().UnicastAddresses)
                    if (u.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        var b = u.Address.GetAddressBytes();
                        l.Add(string.Format("{0}.{1}.{2}.0/24", b[0], b[1], b[2]));
                    }
            }
            return l.Distinct().ToList();
        }
        public static List<string> VmAddresses()
        {
            var l = new List<string>();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                if (Regex.IsMatch(ni.Name + " " + ni.Description, "VMnet|vEthernet|VirtualBox|Hyper-V", RegexOptions.IgnoreCase))
                    foreach (var u in ni.GetIPProperties().UnicastAddresses)
                        if (u.Address.AddressFamily == AddressFamily.InterNetwork) l.Add(u.Address.ToString());
            return l;
        }
        public static string FirewallRule { get { return "DFIR VAO Agent " + S.Port; } }
        public static void Firewall(bool on)
        {
            string o;
            Run("netsh.exe", "advfirewall firewall delete rule name=\"" + FirewallRule + "\"", out o, 30000);
            if (!on) return;
            var nets = VmSubnets();
            if (nets.Count == 0) { Log(T("! віртуальних адаптерів не знайдено: порт НЕ відкрито", "! no virtual adapters found: the port is NOT opened")); return; }
            int rc = Run("netsh.exe", "advfirewall firewall add rule name=\"" + FirewallRule + "\" dir=in action=allow protocol=TCP localport=" + S.Port
                + " remoteip=" + string.Join(",", nets), out o, 30000);
            Log(rc == 0 ? T("Порт ", "Port ") + S.Port + T(" відкрито лише для ", " open only for ") + string.Join(", ", nets) : "netsh: " + o.Trim());
        }
        const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        public static string AutostartState()
        {
            string o;
            if (Run("schtasks.exe", "/Query /TN \"" + S.TaskName + "\"", out o, 15000) == 0) return "task";
            using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunKey))
                if (k != null && k.GetValue(S.TaskName) != null) return "run-key";
            return "off";
        }
        public static void Autostart(bool on)
        {
            string exe = System.Reflection.Assembly.GetExecutingAssembly().Location, o;
            string cmd = "\"" + exe + "\" --serve --home \"" + Home + "\"";
            if (!on)
            {
                Run("schtasks.exe", "/Delete /F /TN \"" + S.TaskName + "\"", out o, 15000);
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunKey, true)) if (k != null && k.GetValue(S.TaskName) != null) k.DeleteValue(S.TaskName);
                Log(T("автозапуск вимкнено", "autostart off")); return;
            }
            if (IsAdmin())
            {
                // SYSTEM at boot: up after a power cut before anyone logs in
                int rc = Run("schtasks.exe", "/Create /F /TN \"" + S.TaskName + "\" /SC ONSTART /RU SYSTEM /RL HIGHEST /TR \"" + cmd.Replace("\"", "\\\"") + "\"", out o, 30000);
                if (rc != 0) throw new Exception("schtasks: " + o);
                Log(T("автозапуск: задача ", "autostart: task ") + S.TaskName + T(" (SYSTEM, при старті Windows)", " (SYSTEM, at Windows start)"));
            }
            else
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(RunKey)) k.SetValue(S.TaskName, cmd);
                Log(T("автозапуск: при вході користувача (для старту без входу запустіть від адміністратора)",
                      "autostart: at user logon (run as administrator to start before logon)"));
            }
        }

        // ------------------------------------------------------------------ update
        public static string CheckUpdate()
        {
            var l = LatestLlama()[0].Tag; var s = LatestSwap().Tag;
            var msg = new List<string>();
            if (l != CurrentTag()) msg.Add("llama.cpp " + (CurrentTag() == "" ? "-" : CurrentTag()) + " -> " + l);
            if (s != S.SwapTag) msg.Add("llama-swap " + (S.SwapTag == "" ? "-" : S.SwapTag) + " -> " + s);
            return string.Join("; ", msg);
        }
        // new build in a side folder -> trial run -> switch -> health through llama-swap -> else back
        public static void Update(string fromZip)
        {
            var before = CurrentTag();
            var tag = InstallLlama(fromZip);
            if (tag == before) { Log(T("llama.cpp вже найновіша: ", "llama.cpp is already the newest: ") + tag); Prune(tag); return; }
            string why;
            if (SwapAlive(out why))
            {
                // unload so the next request starts the new llama-server, then ask one real question
                try { Http("http://127.0.0.1:" + S.SwapPort + "/unload", 60000); } catch { }
                if (!AskModel(out why) && before != "")
                {
                    PointCurrent(before); S.LlamaTag = before; SaveSettings();
                    try { Http("http://127.0.0.1:" + S.SwapPort + "/unload", 60000); } catch { }
                    Thread.Sleep(2000);  // let llama-swap release the failed build's files
                    try { Directory.Delete(Path.Combine(LlamaDir, tag), true); } catch { }
                    throw new Exception(T("нова збірка не відповіла (" + why + "): повернуто " + before, "the new build did not answer (" + why + "): rolled back to " + before));
                }
                Log(T("перевірка відповіддю моделі: OK", "checked with a model answer: OK"));
            }
            Prune(tag, before);
            Log("llama.cpp " + (before == "" ? "-" : before) + " -> " + tag);
        }
        static bool SwapAlive(out string why)
        {
            try { Http("http://127.0.0.1:" + S.SwapPort + "/v1/models", 5000); why = ""; return true; }
            catch (Exception e) { why = e.Message; return false; }
        }
        public static bool AskModel(out string why)
        {
            try
            {
                var r = (HttpWebRequest)WebRequest.Create("http://127.0.0.1:" + S.SwapPort + "/v1/chat/completions");
                r.Method = "POST"; r.ContentType = "application/json"; r.Timeout = 900000;
                var body = Encoding.UTF8.GetBytes("{\"model\":\"gpt-small-20b\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"Say OK\"}]}");
                using (var s = r.GetRequestStream()) s.Write(body, 0, body.Length);
                using (var resp = r.GetResponse()) using (var sr = new StreamReader(resp.GetResponseStream()))
                {
                    var t = sr.ReadToEnd(); why = ""; return t.Contains("\"choices\"");
                }
            }
            catch (Exception e) { why = e.Message; return false; }
        }

        // ------------------------------------------------------------------ main
        [System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern bool AttachConsole(int pid);
        [STAThread]
        public static int Main(string[] args)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DefaultConnectionLimit = 256;
            string cmd = "", arg = "", fromZip = "", shot = "";
            bool models = true; var over = new Dictionary<string, string>();
            for (int i = 0; i < args.Length; i++)
            {
                var a = args[i];
                Func<string> next = () => i + 1 < args.Length ? args[++i] : "";
                switch (a)
                {
                    case "--home": Home = next(); break;
                    case "--lang": Uk = next() == "uk"; break;
                    case "--fake-gpus": FakeGpus = next(); break;
                    case "--no-models": models = false; break;
                    case "--from-zip": fromZip = next(); break;
                    case "--port": case "--swap-port": case "--profile": case "--parallel": case "--task-name": over[a] = next(); break;
                    case "--gui-shot": shot = next(); break;
                    default:
                        if (a.StartsWith("--") && cmd == "") cmd = a;
                        else arg = a;
                        break;
                }
            }
            try { LoadSettings(); }
            catch (Exception e) { AttachConsole(-1); Console.WriteLine("ERROR: " + e.Message); return 1; }
            if (over.ContainsKey("--port")) S.Port = int.Parse(over["--port"]);
            if (over.ContainsKey("--swap-port")) S.SwapPort = int.Parse(over["--swap-port"]);
            if (over.ContainsKey("--profile")) S.Profile = over["--profile"];
            if (over.ContainsKey("--parallel")) S.Parallel = int.Parse(over["--parallel"]);
            if (over.ContainsKey("--task-name")) S.TaskName = over["--task-name"];
            if (cmd == "" || shot != "")
            {
                if (Environment.UserInteractive) { System.Windows.Forms.Application.EnableVisualStyles(); }
                var f = new AgentForm();
                if (shot != "") return f.Shot(shot);
                System.Windows.Forms.Application.Run(f);
                return 0;
            }
            AttachConsole(-1);  // winexe: print into the console it was started from
            try { Console.OutputEncoding = Encoding.UTF8; } catch { }
            try
            {
                string why;
                switch (cmd)
                {
                    case "--detect":
                        foreach (var g in Gpus()) Console.WriteLine("{0}|{1}|{2}|{3}|{4}", g.Index, g.Name, g.TotalMb, g.UsedMb, g.Util);
                        return 0;
                    case "--plan":
                    {
                        var g = Gpus(); var p = PickProfile(g, S.Profile, out why);
                        if (p == "") { Console.WriteLine(why); return 2; }
                        Console.WriteLine("profile=" + p + " gpus=" + g.Count + " total_gb=" + g.Sum(x => x.GB));
                        foreach (var k in ModelsFor(p)) Console.WriteLine("model {0} {1:0.0} GB", Catalog[k].File, Catalog[k].GB);
                        return 0;
                    }
                    case "--gen-config":
                    {
                        var g = Gpus(); var p = PickProfile(g, S.Profile, out why);
                        if (p == "") { Console.WriteLine(why); return 2; }
                        File.WriteAllText(arg, GenConfig(g, p), new UTF8Encoding(false)); return 0;
                    }
                    case "--install": Install(models); return 0;
                    case "--serve": return Serve();
                    case "--status": Console.WriteLine(Http("http://127.0.0.1:" + S.Port + "/agent/status?token=" + S.Token, 15000)); return 0;
                    case "--hello": Console.WriteLine(Http("http://127.0.0.1:" + S.Port + "/agent/hello", 15000)); return 0;
                    case "--check-update": { var u = CheckUpdate(); Console.WriteLine(u == "" ? "up-to-date" : u); return u == "" ? 0 : 3; }
                    case "--update": Update(fromZip); return 0;
                    case "--autostart": Autostart(arg != "off"); Console.WriteLine(AutostartState()); return 0;
                    case "--token":
                        if (arg == "new" || S.Token == "") { S.Token = NewToken(); SaveSettings(); }
                        Console.WriteLine(S.Token); return 0;
                }
                Console.WriteLine("unknown command " + cmd); return 64;
            }
            catch (Exception e) { Console.WriteLine("ERROR: " + e.Message); return 1; }
        }
    }
}
