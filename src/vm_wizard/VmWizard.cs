// DFIR VAO VM Wizard: makes the Linux machine for the DFIR bot on this Windows PC and installs the bot
// in it without questions. WSL2 (GPU straight from the Windows driver), VMware Workstation, Hyper-V or
// VirtualBox. Ubuntu 24.04 comes from cloud-images.ubuntu.com (SHA-256 against SHA256SUMS), the guest
// gets a NoCloud seed (cloud-init) or, under WSL, the same files copied in; inside, installer/guest/
// dfir-guest-bootstrap.sh runs install.sh --answers with the Host Agent address + token.
// C# 5 (.NET Framework csc): no string interpolation, no ?. operators.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace DfirVao
{
    public class Hv
    {
        public string Id, Name, Tool, Note; public bool Ok;
        public override string ToString() { return Name + (Ok ? "" : " (" + Note + ")"); }
    }

    public class Spec
    {
        public string Hv = "wsl", Name = "dfir-vao", Dir = "", Repo = "", RepoRef = "", AgentHome = "";
        public int RamGb = 16, Cpus = 4, DiskGb = 200;
        public bool TestTgStub, Start = true, PlanOnly;
        public string SshPubKey = "", GuestPassword = "", AnswersFile = "", CacheDir = "";
        public Dictionary<string, string> Set = new Dictionary<string, string>();
    }

    public static class Wiz
    {
        public const string Version = "1.0";
        public const string Marker = "dfir-vao-wizard.owner";      // only folders with it are ever removed
        public static Action<string> Log = Console.WriteLine;
        const string Cloud = "https://cloud-images.ubuntu.com/releases/noble/release/";
        const string WslRel = "https://cloud-images.ubuntu.com/wsl/releases/24.04/current/";

        // ---------------------------------------------------------------- detection
        public static string VmwareDir()
        {
            foreach (var k in new[] { @"SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation", @"SOFTWARE\VMware, Inc.\VMware Workstation" })
                try
                {
                    using (var r = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(k))
                        if (r != null && r.GetValue("InstallPath") != null) return r.GetValue("InstallPath").ToString();
                }
                catch { }
            var d = @"C:\Program Files (x86)\VMware\VMware Workstation\";
            return File.Exists(d + "vmrun.exe") ? d : null;
        }

        public static string VboxManage()
        {
            var env = Environment.GetEnvironmentVariable("VBOX_MSI_INSTALL_PATH") ?? Environment.GetEnvironmentVariable("VBOX_INSTALL_PATH");
            foreach (var d in new[] { env, @"C:\Program Files\Oracle\VirtualBox\" })
                if (!string.IsNullOrEmpty(d) && File.Exists(Path.Combine(d, "VBoxManage.exe"))) return Path.Combine(d, "VBoxManage.exe");
            return null;
        }

        public static List<Hv> Detect()
        {
            var l = new List<Hv>();
            var wsl = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe");
            var w = new Hv { Id = "wsl", Name = "WSL2 (GPU from the Windows driver, no copy of the models)", Tool = wsl };
            if (!File.Exists(wsl)) { w.Note = "wsl.exe missing: Windows 10 2004+ / 11 needed"; }
            else
            {
                var r = Run(wsl, "--status", 120, null, true);
                w.Ok = r.Code == 0 && r.Out.IndexOf("2", StringComparison.Ordinal) >= 0;
                w.Note = w.Ok ? "" : "run 'wsl --install --no-distribution' as administrator, then restart Windows";
            }
            l.Add(w);
            var vm = VmwareDir();
            l.Add(new Hv { Id = "vmware", Name = "VMware Workstation", Tool = vm == null ? null : Path.Combine(vm, "vmrun.exe"), Ok = vm != null, Note = vm == null ? "not installed" : "" });
            var hyper = Run("powershell.exe", "-NoProfile -Command \"(Get-Command New-VM -ErrorAction SilentlyContinue) -ne $null\"", 60, null, true);
            bool hok = hyper.Out.Trim().EndsWith("True");
            l.Add(new Hv { Id = "hyperv", Name = "Hyper-V", Tool = "powershell.exe", Ok = hok, Note = hok ? "" : "Hyper-V module not installed (Windows Pro + feature Microsoft-Hyper-V-All)" });
            var vb = VboxManage();
            l.Add(new Hv { Id = "virtualbox", Name = "VirtualBox", Tool = vb, Ok = vb != null, Note = vb == null ? "not installed" : "" });
            return l;
        }

        // ---------------------------------------------------------------- processes
        public class R { public int Code; public string Out; }
        public static R Run(string exe, string args, int timeoutSec, Action<string> live, bool utf16Wsl)
        {
            var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            psi.EnvironmentVariables["WSL_UTF8"] = "1";
            var sb = new StringBuilder();
            try
            {
                using (var p = Process.Start(psi))
                {
                    DataReceivedEventHandler h = (s, e) => { if (e.Data == null) return; lock (sb) sb.AppendLine(e.Data); if (live != null) live(e.Data); };
                    p.OutputDataReceived += h; p.ErrorDataReceived += h;
                    p.BeginOutputReadLine(); p.BeginErrorReadLine();
                    if (!p.WaitForExit(timeoutSec * 1000)) { try { p.Kill(); } catch { } return new R { Code = -9, Out = sb + "\n(timeout)" }; }
                    p.WaitForExit();
                    return new R { Code = p.ExitCode, Out = sb.ToString().Replace("\0", "") };
                }
            }
            catch (Exception e) { return new R { Code = -1, Out = e.Message }; }
        }

        static void Must(R r, string what)
        {
            if (r.Code != 0) throw new Exception(what + " failed (" + r.Code + "): " + Tail(r.Out, 800));
        }
        static string Tail(string s, int n) { s = s ?? ""; return s.Length > n ? s.Substring(s.Length - n) : s; }
        static string Q(string s) { return "\"" + s.Replace("\"", "\\\"") + "\""; }

        // ---------------------------------------------------------------- downloads
        public static string Cache(Spec s)
        {
            var d = string.IsNullOrEmpty(s.CacheDir)
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DFIR_VAO_Wizard", "images") : s.CacheDir;
            Directory.CreateDirectory(d); return d;
        }

        static WebClient Web()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var w = new WebClient(); w.Headers["User-Agent"] = "dfir-vao-vm-wizard/" + Version; return w;
        }

        // a dropped DNS/network (e.g. right after a power cut) must not end the whole install: 5 tries, 10..60 s apart
        static T Retry<T>(string what, Func<T> f)
        {
            int[] wait = { 10, 20, 40, 60 };
            for (int i = 0; ; i++)
            {
                try { return f(); }
                catch (Exception e)
                {
                    var inner = e is AggregateException && e.InnerException != null ? e.InnerException : e;
                    if (i >= wait.Length) throw inner;
                    Log(string.Format("{0}: {1} - retry {2}/{3} in {4} s", what, inner.Message, i + 1, wait.Length, wait[i]));
                    System.Threading.Thread.Sleep(wait[i] * 1000);
                }
            }
        }

        public static string Sha256(string path)
        {
            using (var f = File.OpenRead(path)) using (var h = SHA256.Create())
                return BitConverter.ToString(h.ComputeHash(f)).Replace("-", "").ToLowerInvariant();
        }

        // official image + SHA256SUMS of the same folder; a cached file is re-used only if the sum still matches
        public static string Image(Spec s, string baseUrl, string file)
        {
            string sums = Retry("SHA256SUMS", () => { using (var w = Web()) return w.DownloadString(baseUrl + "SHA256SUMS"); });
            var m = Regex.Match(sums, "^([0-9a-f]{64}) [ *]" + Regex.Escape(file) + "\\s*$", RegexOptions.Multiline);
            if (!m.Success) throw new Exception(file + " is not in " + baseUrl + "SHA256SUMS");
            var want = m.Groups[1].Value;
            var dst = Path.Combine(Cache(s), file);
            if (File.Exists(dst) && Sha256(dst) == want) { Log("image " + file + ": cached, SHA-256 ok"); return dst; }
            Log("downloading " + baseUrl + file);
            Retry(file, () =>
            {
                using (var w = Web())
                {
                    long last = 0;
                    w.DownloadProgressChanged += (o, e) => { if (e.BytesReceived - last > 100L << 20) { last = e.BytesReceived; Log(string.Format("  {0} MB", e.BytesReceived >> 20)); } };
                    var t = w.DownloadFileTaskAsync(baseUrl + file, dst + ".part"); t.Wait();
                }
                return true;
            });
            var got = Sha256(dst + ".part");
            if (got != want) { File.Delete(dst + ".part"); throw new Exception("SHA-256 mismatch for " + file + ": " + got + " != " + want); }
            if (File.Exists(dst)) File.Delete(dst);
            File.Move(dst + ".part", dst);
            File.AppendAllText(Path.Combine(Cache(s), "provenance.jsonl"), string.Format("{{\"time\":\"{0:o}\",\"file\":\"{1}\",\"url\":\"{2}\",\"sha256\":\"{3}\"}}\n", DateTime.UtcNow, file, baseUrl + file, want));
            Log("image " + file + ": SHA-256 ok " + want);
            return dst;
        }

        // ---------------------------------------------------------------- answers
        public class Agent { public int Port; public string Token = ""; public string Home; }
        public static Agent ReadAgent(string home)
        {
            if (string.IsNullOrEmpty(home)) home = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DFIR_VAO_Agent");
            var f = Path.Combine(home, "agent.json");
            if (!File.Exists(f)) return null;
            var d = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(f));
            return new Agent { Home = home, Port = Convert.ToInt32(d["Port"]), Token = d.ContainsKey("Token") ? (d["Token"] ?? "").ToString() : "" };
        }

        // address of this PC as the guest sees it
        public static string HostIpFor(string hv)
        {
            if (hv == "wsl") return "__GATEWAY__";             // WSL2 NAT: the guest's gateway is Windows, new each start
            if (hv == "virtualbox") return "10.0.2.2";         // VirtualBox NAT: fixed host alias
            string want = hv == "vmware" ? "VMnet8" : "Default Switch";
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
                if (n.Name.Contains(want) || n.Description.Contains(want))
                    foreach (var a in n.GetIPProperties().UnicastAddresses)
                        if (a.Address.AddressFamily == AddressFamily.InterNetwork) return a.Address.ToString();
            throw new Exception("no host adapter '" + want + "' (is the hypervisor's NAT network on?)");
        }

        static string Rand(int n)
        {
            const string a = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
            var b = new byte[n]; using (var r = RandomNumberGenerator.Create()) r.GetBytes(b);
            return new string(b.Select(x => a[x % a.Length]).ToArray());
        }

        static string ShQ(string v) { return "'" + v.Replace("'", "'\\''") + "'"; }

        // install_answers.env for install.sh --answers (bash-sourced). Generated passwords go to the summary.
        public static string Answers(Spec s, Agent ag, List<string> summary)
        {
            var a = new Dictionary<string, string>();
            if (!string.IsNullOrEmpty(s.AnswersFile))
                foreach (var line in File.ReadAllLines(s.AnswersFile))
                {
                    var m = Regex.Match(line, "^([A-Z_][A-Z0-9_]*)=(.*)$");
                    if (m.Success) a[m.Groups[1].Value] = Unq(m.Groups[2].Value);
                }
            foreach (var kv in s.Set) a[kv.Key] = kv.Value;
            if (!a.ContainsKey("LLM_MODE") && ag != null)
            {
                a["LLM_MODE"] = "server";
                a["LLM_BASE_URL"] = "http://" + HostIpFor(s.Hv) + ":" + ag.Port + "/v1";
                a["LLM_NEEDS_KEY"] = "y"; a["LLM_API_KEY"] = ag.Token;
            }
            Def(a, "WG_ENABLE", "n");
            Def(a, "WEBUI_ADMIN_EMAIL", "admin@dfirbot.com");
            Def(a, "PGADMIN_DEFAULT_EMAIL", a["WEBUI_ADMIN_EMAIL"]);
            foreach (var k in new[] { "WEBUI_ADMIN_PASSWORD", "PGADMIN_DEFAULT_PASSWORD", "POSTGRES_PASSWORD" })
                if (!a.ContainsKey(k)) { a[k] = Rand(20); summary.Add(k + " = " + a[k]); }
            foreach (var k in new[] { "INSTALL_LANG", "ACCEPT_TERMS", "DFIR_TG_BOT_TOKEN", "OWNER_CHAT_ID", "TUNNEL", "NGROK_URL" })
                if (!a.ContainsKey(k)) throw new Exception("answer " + k + " is missing (--set " + k + "=... or the window)");
            if (a["ACCEPT_TERMS"] != "yes") throw new Exception("ACCEPT_TERMS must be yes: the licence terms have to be accepted");
            var sb = new StringBuilder("# DFIR VAO VM Wizard " + Version + " " + DateTime.Now.ToString("s") + ". Contains secrets.\n");
            foreach (var kv in a) sb.Append(kv.Key).Append('=').Append(ShQ(kv.Value)).Append('\n');
            return sb.ToString();
        }
        static void Def(Dictionary<string, string> a, string k, string v) { if (!a.ContainsKey(k)) a[k] = v; }
        static string Unq(string v)
        {
            v = v.Trim();
            if (v.Length >= 2 && v[0] == '\'' && v[v.Length - 1] == '\'') return v.Substring(1, v.Length - 2).Replace("'\\''", "'");
            if (v.Length >= 2 && v[0] == '"' && v[v.Length - 1] == '"') return v.Substring(1, v.Length - 2);
            return Regex.Replace(v, @"\\(.)", "$1");   // bash printf %q
        }

        public static string WizardEnv(Spec s, string repoInGuest)
        {
            var sb = new StringBuilder();
            sb.Append("REPO_SRC=").Append(ShQ(repoInGuest)).Append('\n');
            if (!string.IsNullOrEmpty(s.RepoRef)) sb.Append("REPO_REF=").Append(ShQ(s.RepoRef)).Append('\n');
            sb.Append("DEST=/opt/dfir-vao\n");
            if (s.TestTgStub) sb.Append("TEST_TG_STUB=1\n");
            return sb.ToString();
        }

        public static string Res(string name)
        {
            using (var st = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
            using (var r = new StreamReader(st)) return r.ReadToEnd().Replace("\r\n", "\n");
        }

        // cloud-init user-data: user + key, grow the disk, copy the wizard files from the seed, start the bootstrap unit
        public static string UserData(Spec s)
        {
            var sb = new StringBuilder("#cloud-config\n");
            sb.Append("hostname: ").Append(Regex.Replace(s.Name.ToLowerInvariant(), "[^a-z0-9-]", "-")).Append('\n');
            sb.Append("users:\n  - name: dfir\n    groups: [sudo]\n    shell: /bin/bash\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    lock_passwd: false\n");
            if (!string.IsNullOrEmpty(s.SshPubKey)) sb.Append("    ssh_authorized_keys:\n      - ").Append(s.SshPubKey.Trim()).Append('\n');
            sb.Append("chpasswd:\n  expire: false\n  users:\n    - {name: dfir, password: ").Append(ShQ(s.GuestPassword)).Append(", type: text}\n");
            sb.Append("ssh_pwauth: true\ngrowpart: {mode: auto, devices: ['/']}\nresize_rootfs: true\n");
            sb.Append("write_files:\n  - path: /etc/systemd/system/dfir-wizard.service\n    content: |\n");
            sb.Append("      [Unit]\n      Description=DFIR VAO first install (VM wizard)\n      Wants=network-online.target\n      After=network-online.target cloud-final.service\n");
            sb.Append("      [Service]\n      Type=oneshot\n      ExecStart=/usr/local/sbin/dfir-guest-bootstrap\n      TimeoutStartSec=0\n      RemainAfterExit=yes\n");
            sb.Append("      [Install]\n      WantedBy=multi-user.target\n");
            sb.Append("runcmd:\n");
            sb.Append("  - [sh, -c, 'mkdir -p /etc/dfir-wizard /var/lib/dfir-wizard /mnt/dfir-seed && (mount -o ro LABEL=CIDATA /mnt/dfir-seed || mount -o ro LABEL=cidata /mnt/dfir-seed)']\n");
            sb.Append("  - [sh, -c, 'cp /mnt/dfir-seed/wizard.env /mnt/dfir-seed/install_answers.env /etc/dfir-wizard/ && chmod 600 /etc/dfir-wizard/*']\n");
            sb.Append("  - [sh, -c, 'install -m 755 /mnt/dfir-seed/bootstrap.sh /usr/local/sbin/dfir-guest-bootstrap']\n");
            sb.Append("  - [sh, -c, 'if [ -f /mnt/dfir-seed/repo.tar.gz ]; then cp /mnt/dfir-seed/repo.tar.gz /var/lib/dfir-wizard/; fi; umount /mnt/dfir-seed']\n");
            sb.Append("  - [systemctl, daemon-reload]\n  - [systemctl, enable, dfir-wizard.service]\n  - [systemctl, start, --no-block, dfir-wizard.service]\n");
            return sb.ToString();
        }

        // ---------------------------------------------------------------- ISO 9660 + Joliet via IMAPI2 (part of Windows)
        [ComImport, Guid("0000000c-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IStreamRaw
        {
            void Read([Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pv, int cb, IntPtr pcbRead);
        }
        public static void MakeSeedIso(string iso, Dictionary<string, string> files)
        {
            var t = Type.GetTypeFromProgID("IMAPI2FS.MsftFileSystemImage");
            dynamic fs = Activator.CreateInstance(t);
            fs.FileSystemsToCreate = 3;            // ISO 9660 + Joliet: Joliet keeps "user-data" as is
            fs.VolumeName = "CIDATA";
            dynamic root = fs.Root;
            var tmp = new List<string>();
            foreach (var kv in files)
            {
                var src = kv.Value;
                var ist = SHCreateStreamOnFile(src);
                root.AddFile(kv.Key, ist);
            }
            dynamic res = fs.CreateResultImage();
            object st = res.ImageStream;
            var raw = (IStreamRaw)st;
            using (var o = File.Create(iso))
            {
                var buf = new byte[1 << 20]; var pRead = Marshal.AllocHGlobal(4);
                try
                {
                    while (true)
                    {
                        raw.Read(buf, buf.Length, pRead);
                        int n = Marshal.ReadInt32(pRead);
                        if (n <= 0) break;
                        o.Write(buf, 0, n);
                    }
                }
                finally { Marshal.FreeHGlobal(pRead); }
            }
        }
        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        static extern void SHCreateStreamOnFileEx(string file, uint mode, uint attr, bool create, IntPtr template, [MarshalAs(UnmanagedType.Interface)] out object stream);
        static object SHCreateStreamOnFile(string f) { object s; SHCreateStreamOnFileEx(f, 0x20 /*STGM_SHARE_DENY_WRITE*/, 0, false, IntPtr.Zero, out s); return s; }

        // ---------------------------------------------------------------- create
        public static List<string> Create(Spec s)
        {
            var summary = new List<string>();
            if (!Regex.IsMatch(s.Name, "^[A-Za-z0-9][A-Za-z0-9._-]{1,40}$")) throw new Exception("bad name: letters, digits . _ - only");
            if (string.IsNullOrEmpty(s.Dir)) s.Dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "DFIR_VAO_VMs", s.Name);
            if (Directory.Exists(s.Dir) && Directory.EnumerateFileSystemEntries(s.Dir).Any())
            {
                // a previous try of the SAME VM stopped before the VM existed (no network, power cut): start again
                if (!HalfMade(s)) throw new Exception("folder not empty: " + s.Dir);
                Log("previous attempt stopped before the VM was made: clearing " + s.Dir);
                Directory.Delete(s.Dir, true);
            }
            if (string.IsNullOrEmpty(s.Repo)) throw new Exception("--repo: git URL of the project or a .tar.gz of it");
            if (string.IsNullOrEmpty(s.GuestPassword)) { s.GuestPassword = Rand(16); summary.Add("Linux user dfir password = " + s.GuestPassword); }
            var ag = ReadAgent(s.AgentHome);
            if (ag == null && !s.Set.ContainsKey("LLM_MODE")) throw new Exception("no DFIR VAO Host Agent here (agent.json) and no LLM_MODE given");
            if (ag != null) Log("Host Agent: port " + ag.Port + (ag.Token == "" ? " (no token!)" : ", token found"));

            Directory.CreateDirectory(s.Dir);
            File.WriteAllText(Path.Combine(s.Dir, Marker), "created by DFIR VAO VM Wizard " + Version + " " + DateTime.Now.ToString("s") + " hv=" + s.Hv + " name=" + s.Name + "\n");
            var seed = Path.Combine(s.Dir, "seed"); Directory.CreateDirectory(seed);
            bool localRepo = File.Exists(s.Repo);
            File.WriteAllText(Path.Combine(seed, "install_answers.env"), Answers(s, ag, summary), new UTF8Encoding(false));
            File.WriteAllText(Path.Combine(seed, "wizard.env"), WizardEnv(s, localRepo ? "/var/lib/dfir-wizard/repo.tar.gz" : s.Repo), new UTF8Encoding(false));
            File.WriteAllText(Path.Combine(seed, "bootstrap.sh"), Res("dfir-guest-bootstrap.sh"), new UTF8Encoding(false));
            if (localRepo) File.Copy(s.Repo, Path.Combine(seed, "repo.tar.gz"));
            if (s.Hv != "wsl")
            {
                File.WriteAllText(Path.Combine(seed, "user-data"), UserData(s), new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(seed, "meta-data"), "instance-id: dfir-vao-" + Guid.NewGuid().ToString("N").Substring(0, 12) + "\nlocal-hostname: " + s.Name.ToLowerInvariant() + "\n", new UTF8Encoding(false));
                var iso = Path.Combine(s.Dir, "seed.iso");
                MakeSeedIso(iso, Directory.GetFiles(seed).ToDictionary(f => Path.GetFileName(f), f => f));
                Log("seed ISO (cloud-init NoCloud): " + iso);
            }
            switch (s.Hv)
            {
                case "wsl": CreateWsl(s, seed); break;
                case "vmware": CreateVmware(s); break;
                case "virtualbox": CreateVbox(s); break;
                case "hyperv": CreateHyperV(s); break;
                default: throw new Exception("unknown hypervisor " + s.Hv);
            }
            if (s.Hv != "wsl")   // the answers live on in the ISO for the first boot only; the folder copy goes now
                foreach (var f in new[] { "install_answers.env", "wizard.env" }) File.Delete(Path.Combine(seed, f));
            return summary;
        }

        static string Wsl() { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"); }
        static string WinToWsl(string p) { var f = Path.GetFullPath(p); return "/mnt/" + char.ToLowerInvariant(f[0]) + f.Substring(2).Replace('\\', '/'); }

        public static bool WslExists(string name)
        {
            var r = Run(Wsl(), "--list --quiet", 60, null, true);
            return r.Out.Split('\n').Any(l => l.Trim() == name);
        }

        static void CreateWsl(Spec s, string seed)
        {
            if (WslExists(s.Name)) throw new Exception("WSL distribution " + s.Name + " already exists");
            var img = Image(s, WslRel, "ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz");
            if (s.PlanOnly) { Log("plan: wsl --import " + s.Name + " " + s.Dir + "\\disk " + img + " --version 2"); return; }
            Must(Run(Wsl(), "--import " + s.Name + " " + Q(Path.Combine(s.Dir, "disk")) + " " + Q(img) + " --version 2", 900, Log, true), "wsl --import");
            Log("WSL distribution " + s.Name + " imported");
            string sd = WinToWsl(seed);
            // a script file, not bash -c: no quoting through wsl.exe's command line
            var setup = "set -e\nprintf '[boot]\\nsystemd=true\\n[user]\\ndefault=root\\n[network]\\nhostname=%s\\n' '" + s.Name + "' > /etc/wsl.conf\n" +
                "mkdir -p /etc/dfir-wizard /var/lib/dfir-wizard\ncp '" + sd + "/wizard.env' '" + sd + "/install_answers.env' /etc/dfir-wizard/\nchmod 600 /etc/dfir-wizard/*\n" +
                "install -m 755 '" + sd + "/bootstrap.sh' /usr/local/sbin/dfir-guest-bootstrap\n" +
                "if [ -f '" + sd + "/repo.tar.gz' ]; then cp '" + sd + "/repo.tar.gz' /var/lib/dfir-wizard/; fi\n";
            File.WriteAllText(Path.Combine(seed, "wsl_setup.sh"), setup, new UTF8Encoding(false));
            Must(Run(Wsl(), "-d " + s.Name + " -u root --exec /bin/bash " + Q(sd + "/wsl_setup.sh"), 300, Log, true), "WSL first setup");
            foreach (var f in new[] { "install_answers.env", "wizard.env", "repo.tar.gz", "wsl_setup.sh" }) { var p = Path.Combine(seed, f); if (File.Exists(p)) File.Delete(p); }
            Must(Run(Wsl(), "--terminate " + s.Name, 60, Log, true), "wsl --terminate (systemd on)");
            if (!s.Start) return;
            Log("installing inside WSL (long: Docker, images, models); log /var/log/dfir-wizard.log in the guest");
            Run(Wsl(), "-d " + s.Name + " -u root --exec /usr/local/sbin/dfir-guest-bootstrap", 6 * 3600, null, true);
            var st = Run(Wsl(), "-d " + s.Name + " -u root --exec cat /var/lib/dfir-wizard/status", 60, null, true).Out.Trim();
            Log("guest status: " + st);
            if (st != "ok") throw new Exception("install inside WSL ended with " + st + "; see /var/log/dfir-wizard.log in " + s.Name);
            Keepalive(s.Name, true);
        }

        // WSL stops an idle distribution: the bot needs it running, so a hidden wsl.exe holds it at logon
        public static void Keepalive(string name, bool on)
        {
            using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
            {
                var v = "DFIR_VAO_WSL_" + name;
                if (on) k.SetValue(v, "\"" + Assembly.GetExecutingAssembly().Location + "\" --keepalive " + name); else k.DeleteValue(v, false);
            }
            if (on)
                // ShellExecute: the keepalive (and its wsl.exe children) must NOT inherit our stdout/stderr, or whoever
                // reads the wizard's output through a pipe (PowerShell `| Out-String`, a script) waits for ever
                Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--keepalive " + name) { UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden });
        }
        public static void KeepaliveLoop(string name)
        {
            while (true)
            {
                Run(Wsl(), "-d " + name + " -u root --exec sleep infinity", int.MaxValue / 1000, null, true);
                System.Threading.Thread.Sleep(30000);
            }
        }

        // cloud disk: VMDK (stream-optimized) -> Workstation format, grown; the guest grows / at boot
        static void CreateVmware(Spec s)
        {
            var vm = VmwareDir(); if (vm == null) throw new Exception("VMware Workstation not found");
            var img = Image(s, Cloud, "ubuntu-24.04-server-cloudimg-amd64.vmdk");
            var disk = Path.Combine(s.Dir, "disk.vmdk");
            var vdm = Path.Combine(vm, "vmware-vdiskmanager.exe");
            if (s.PlanOnly) { Log("plan: vdiskmanager -r, -x " + s.DiskGb + "GB; vmx; vmrun start"); return; }
            Must(Run(vdm, "-r " + Q(img) + " -t 0 " + Q(disk), 900, null, false), "vmware-vdiskmanager convert");
            Must(Run(vdm, "-x " + s.DiskGb + "GB " + Q(disk), 900, null, false), "vmware-vdiskmanager grow");
            var vmx = Path.Combine(s.Dir, s.Name + ".vmx");
            var lines = new[] {
                ".encoding = \"UTF-8\"", "config.version = \"8\"", "virtualHW.version = \"19\"",
                "displayName = \"" + s.Name + "\"", "guestOS = \"ubuntu-64\"",
                "memsize = \"" + (s.RamGb * 1024) + "\"", "numvcpus = \"" + s.Cpus + "\"",
                "pciBridge0.present = \"TRUE\"",
                "pciBridge4.present = \"TRUE\"", "pciBridge4.virtualDev = \"pcieRootPort\"", "pciBridge4.functions = \"8\"",
                "pciBridge5.present = \"TRUE\"", "pciBridge5.virtualDev = \"pcieRootPort\"", "pciBridge5.functions = \"8\"",
                "pciBridge6.present = \"TRUE\"", "pciBridge6.virtualDev = \"pcieRootPort\"", "pciBridge6.functions = \"8\"",
                "pciBridge7.present = \"TRUE\"", "pciBridge7.virtualDev = \"pcieRootPort\"", "pciBridge7.functions = \"8\"",
                "scsi0.present = \"TRUE\"", "scsi0.virtualDev = \"pvscsi\"",
                "scsi0:0.present = \"TRUE\"", "scsi0:0.fileName = \"disk.vmdk\"",
                "sata0.present = \"TRUE\"", "sata0:1.present = \"TRUE\"", "sata0:1.deviceType = \"cdrom-image\"", "sata0:1.fileName = \"seed.iso\"",
                "ethernet0.present = \"TRUE\"", "ethernet0.connectionType = \"nat\"", "ethernet0.virtualDev = \"vmxnet3\"", "ethernet0.addressType = \"generated\"",
                "serial0.present = \"TRUE\"", "serial0.fileType = \"file\"", "serial0.fileName = \"serial.log\"", "serial0.tryNoRxLoss = \"FALSE\"",
                "tools.syncTime = \"TRUE\"", "uuid.action = \"create\"", "msg.autoAnswer = \"TRUE\"" };
            File.WriteAllLines(vmx, lines);
            Log("VMware VM: " + vmx);
            if (s.Start) Must(Run(Path.Combine(vm, "vmrun.exe"), "-T ws start " + Q(vmx) + " nogui", 300, Log, false), "vmrun start");
        }

        static void CreateVbox(Spec s)
        {
            var vb = VboxManage(); if (vb == null && !s.PlanOnly) throw new Exception("VirtualBox not found");
            var img = Image(s, Cloud, "ubuntu-24.04-server-cloudimg-amd64.vmdk");
            var vdi = Path.Combine(s.Dir, "disk.vdi");
            var steps = new List<string> {
                "createvm --name " + Q(s.Name) + " --ostype Ubuntu_64 --register --basefolder " + Q(s.Dir),
                "modifyvm " + Q(s.Name) + " --memory " + (s.RamGb * 1024) + " --cpus " + s.Cpus + " --nic1 nat --uart1 0x3F8 4 --uartmode1 file " + Q(Path.Combine(s.Dir, "serial.log")),
                "clonemedium disk " + Q(img) + " " + Q(vdi) + " --format VDI",
                "modifymedium disk " + Q(vdi) + " --resize " + (s.DiskGb * 1024),
                "storagectl " + Q(s.Name) + " --name SATA --add sata --portcount 2",
                "storageattach " + Q(s.Name) + " --storagectl SATA --port 0 --device 0 --type hdd --medium " + Q(vdi),
                "storageattach " + Q(s.Name) + " --storagectl SATA --port 1 --device 0 --type dvddrive --medium " + Q(Path.Combine(s.Dir, "seed.iso")) };
            if (s.Start) steps.Add("startvm " + Q(s.Name) + " --type headless");
            foreach (var a in steps) { if (s.PlanOnly) Log("plan: VBoxManage " + a); else Must(Run(vb, a, 900, Log, false), "VBoxManage " + a.Split(' ')[0]); }
        }

        // Hyper-V (administrator): the Azure VHD of the same release, generation 1, Default Switch (NAT)
        public static string HyperVScript(Spec s, string vhdTarGz)
        {
            var d = s.Dir.Replace("'", "''");
            return "$ErrorActionPreference='Stop'; Set-Location '" + d + "'; " +
                "tar -xzf '" + vhdTarGz.Replace("'", "''") + "' -C '" + d + "'; " +
                "$v = Get-ChildItem '" + d + "' -Filter *.vhd | Select-Object -First 1; " +
                "Convert-VHD -Path $v.FullName -DestinationPath '" + d + "\\disk.vhdx' -VHDType Dynamic; Remove-Item $v.FullName; " +
                "Resize-VHD -Path '" + d + "\\disk.vhdx' -SizeBytes " + s.DiskGb + "GB; " +
                "New-VM -Name '" + s.Name + "' -Generation 1 -MemoryStartupBytes " + s.RamGb + "GB -VHDPath '" + d + "\\disk.vhdx' -Path '" + d + "' -SwitchName 'Default Switch' | Out-Null; " +
                "Set-VMProcessor -VMName '" + s.Name + "' -Count " + s.Cpus + "; Set-VMMemory -VMName '" + s.Name + "' -DynamicMemoryEnabled $false; " +
                "Set-VMDvdDrive -VMName '" + s.Name + "' -Path '" + d + "\\seed.iso'; " +
                "Set-VMComPort -VMName '" + s.Name + "' -Number 1 -Path '\\\\.\\pipe\\" + s.Name + "-serial'" +
                (s.Start ? "; Start-VM -Name '" + s.Name + "'" : "");
        }
        static void CreateHyperV(Spec s)
        {
            var img = Image(s, Cloud, "ubuntu-24.04-server-cloudimg-amd64-azure.vhd.tar.gz");
            var ps = HyperVScript(s, img);
            if (s.PlanOnly) { Log("plan: powershell " + ps); return; }
            Must(Run("powershell.exe", "-NoProfile -Command " + Q(ps), 1800, Log, false), "Hyper-V");
        }

        // ---------------------------------------------------------------- status / remove
        public static string Status(Spec s)
        {
            if (s.Hv == "wsl")
                return Run(Wsl(), "-d " + s.Name + " -u root --exec cat /var/lib/dfir-wizard/status", 120, null, true).Out.Trim();
            var log = Path.Combine(s.Dir, "serial.log");
            if (!File.Exists(log)) return "no serial log yet";
            string text;
            using (var f = new FileStream(log, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) using (var r = new StreamReader(f)) text = r.ReadToEnd();
            var ms = Regex.Matches(text, "DFIR-WIZARD-STATUS: (\\S+)");
            return ms.Count > 0 ? ms[ms.Count - 1].Groups[1].Value : "booting";
        }

        // our own marker for this hv/name, but the VM itself is not there yet -> safe to clear and redo
        static bool HalfMade(Spec s)
        {
            var mk = Path.Combine(s.Dir, Marker);
            if (!File.Exists(mk) || !File.ReadAllText(mk).Contains("hv=" + s.Hv + " name=" + s.Name + "\n")) return false;
            if (s.Hv == "wsl") return !WslExists(s.Name);
            if (s.Hv == "vmware") return !File.Exists(Path.Combine(s.Dir, s.Name + ".vmx"));
            return false;
        }

        // removes only what this wizard made: the folder must carry the marker with the same name
        public static void Remove(Spec s)
        {
            var mk = Path.Combine(s.Dir, Marker);
            if (!File.Exists(mk) || !File.ReadAllText(mk).Contains("hv=" + s.Hv + " name=" + s.Name + "\n"))
                throw new Exception("refused: " + s.Dir + " has no wizard marker for " + s.Hv + "/" + s.Name);
            if (s.Hv == "wsl")
            {
                Keepalive(s.Name, false);
                foreach (var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().Location)))
                    if (p.Id != Process.GetCurrentProcess().Id) try { if (CmdLine(p).Contains("--keepalive " + s.Name)) p.Kill(); } catch { }
                var lst = Run(Wsl(), "--list --verbose", 60, null, true).Out;
                if (WslExists(s.Name)) Must(Run(Wsl(), "--unregister " + s.Name, 600, Log, true), "wsl --unregister");
            }
            else if (s.Hv == "vmware")
            {
                var vmrun = Path.Combine(VmwareDir(), "vmrun.exe"); var vmx = Path.Combine(s.Dir, s.Name + ".vmx");
                Run(vmrun, "-T ws stop " + Q(vmx) + " hard", 300, Log, false);
                Run(vmrun, "-T ws deleteVM " + Q(vmx), 300, Log, false);
            }
            else if (s.Hv == "virtualbox")
            {
                var vb = VboxManage();
                Run(vb, "controlvm " + Q(s.Name) + " poweroff", 120, Log, false);
                Run(vb, "unregistervm " + Q(s.Name) + " --delete", 300, Log, false);
            }
            else if (s.Hv == "hyperv")
                Run("powershell.exe", "-NoProfile -Command " + Q("Stop-VM -Name '" + s.Name + "' -TurnOff -Force; Remove-VM -Name '" + s.Name + "' -Force"), 300, Log, false);
            Directory.Delete(s.Dir, true);
            Log("removed " + s.Hv + "/" + s.Name + " and " + s.Dir);
        }
        static string CmdLine(Process p)
        {
            using (var q = new System.Management.ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + p.Id))
                foreach (var o in q.Get()) return (o["CommandLine"] ?? "").ToString();
            return "";
        }
    }
}
