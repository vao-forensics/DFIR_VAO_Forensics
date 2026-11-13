// The window: GPUs, agent state and queue, token for the VM installer, install / update / autostart.
// Heavy work runs this same EXE with a CLI command (elevated when it needs admin) and shows its output.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace DfirVao
{
    public class AgentForm : Form
    {
        static string T(string uk, string en) { return Agent.T(uk, en); }
        readonly Label state = new Label(), queue = new Label(), addr = new Label();
        readonly ListView gpus = new ListView();
        readonly TextBox token = new TextBox(), log = new TextBox();
        readonly CheckBox auto = new CheckBox();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();

        public AgentForm()
        {
            Text = "DFIR VAO Host Agent " + Agent.Version;
            Size = new Size(860, 640); Font = new Font("Segoe UI", 9.5f); StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(System.Reflection.Assembly.GetExecutingAssembly().Location); } catch { }

            state.SetBounds(12, 10, 820, 22); state.Font = new Font(Font, FontStyle.Bold);
            queue.SetBounds(12, 34, 820, 22);
            gpus.SetBounds(12, 60, 820, 150); gpus.View = View.Details; gpus.FullRowSelect = true;
            gpus.Columns.Add("GPU", 50); gpus.Columns.Add(T("Карта", "Card"), 330); gpus.Columns.Add(T("Памʼять", "Memory"), 200); gpus.Columns.Add(T("Навантаження", "Load"), 120);

            var tl = new Label { Text = T("Токен для ВМ (інсталятор спитає його):", "Token for the VM (the installer asks for it):") };
            tl.SetBounds(12, 220, 330, 22);
            token.SetBounds(345, 218, 300, 24); token.ReadOnly = true; token.UseSystemPasswordChar = true;
            var show = Btn(T("Показати", "Show"), 650, 216, 85, delegate { token.UseSystemPasswordChar = !token.UseSystemPasswordChar; });
            var copy = Btn(T("Копіювати", "Copy"), 740, 216, 92, delegate { if (Agent.S.Token != "") Clipboard.SetText(Agent.S.Token); });
            addr.SetBounds(12, 248, 820, 22);

            var install = Btn(T("Встановити / полагодити", "Install / repair"), 12, 280, 200, delegate { RunSelf("--install", true); });
            var check = Btn(T("Перевірити оновлення", "Check for updates"), 220, 280, 190, delegate { RunSelf("--check-update", false); });
            var upd = Btn(T("Оновити llama.cpp", "Update llama.cpp"), 418, 280, 170, delegate { RunSelf("--update", false); });
            var newtok = Btn(T("Новий токен", "New token"), 596, 280, 120, delegate {
                if (MessageBox.Show(T("Старий токен перестане працювати, ВМ треба буде дати новий (sudo dfir menu → ШІ). Далі?",
                    "The old token stops working; give the VM the new one (sudo dfir menu → AI). Continue?"), Text, MessageBoxButtons.YesNo) == DialogResult.Yes)
                    RunSelf("--token new", false);
            });
            var folder = Btn(T("Тека", "Folder"), 724, 280, 108, delegate { Process.Start("explorer.exe", Agent.Home); });
            auto.SetBounds(12, 316, 600, 24);
            auto.Text = T("Запускати разом з Windows (з правами адміністратора — ще до входу)", "Start with Windows (as administrator: before anyone logs in)");
            auto.Click += delegate { RunSelf("--autostart " + (auto.Checked ? "on" : "off"), auto.Checked); };

            log.SetBounds(12, 346, 820, 240); log.Multiline = true; log.ScrollBars = ScrollBars.Vertical; log.ReadOnly = true;
            log.Font = new Font("Consolas", 9f); log.BackColor = Color.White;
            Controls.AddRange(new Control[] { state, queue, gpus, tl, token, show, copy, addr, install, check, upd, newtok, folder, auto, log });

            timer.Interval = 3000; timer.Tick += delegate { Refresh2(); };
            Load += delegate { Refresh2(); timer.Start(); };
        }

        Button Btn(string text, int x, int y, int w, EventHandler click)
        {
            var b = new Button { Text = text }; b.SetBounds(x, y, w, 30); b.Click += click; return b;
        }

        public void Refresh2()
        {
            Agent.LoadSettings();
            token.Text = Agent.S.Token == "" ? T("(ще немає — натисніть «Встановити»)", "(none yet: press Install)") : Agent.S.Token;
            var ips = Agent.VmAddresses();
            addr.Text = T("Адреса для ВМ: ", "Address for the VM: ") + (ips.Count == 0 ? T("(віртуальних адаптерів не знайдено)", "(no virtual adapters found)")
                : string.Join("  ", ips.Select(i => "http://" + i + ":" + Agent.S.Port + "/v1")));
            auto.Checked = Agent.AutostartState() != "off";
            Dictionary<string, object> st = null;
            try
            {
                var r = (System.Net.HttpWebRequest)System.Net.WebRequest.Create("http://127.0.0.1:" + Agent.S.Port + "/agent/status");
                r.Timeout = 2500; r.Headers["Authorization"] = "Bearer " + Agent.S.Token;
                using (var resp = r.GetResponse()) using (var sr = new StreamReader(resp.GetResponseStream()))
                    st = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(sr.ReadToEnd());
            }
            catch { }
            gpus.Items.Clear();
            List<Gpu> g = Agent.Gpus();
            foreach (var x in g)
                gpus.Items.Add(new ListViewItem(new[] { x.Index.ToString(), x.Name, string.Format("{0:0.0} / {1:0.0} GB", x.UsedMb / 1024.0, x.TotalMb / 1024.0), x.Util + " %" }));
            if (g.Count == 0) gpus.Items.Add(new ListViewItem(new[] { "-", T("NVIDIA GPU не знайдено (драйвер / nvidia-smi)", "no NVIDIA GPU found (driver / nvidia-smi)"), "", "" }));
            string why; var prof = Agent.PickProfile(g, Agent.S.Profile == "tiny" ? "tiny" : "auto", out why);
            if (st == null)
            {
                state.ForeColor = Color.DarkRed;
                state.Text = T("Агент НЕ працює на порту ", "Agent is NOT running on port ") + Agent.S.Port +
                    (Agent.CurrentTag() == "" ? T(" — ще не встановлено", " — not installed yet") : T(" — увімкніть автозапуск або перезавантажте", " — turn on autostart or restart"));
                queue.Text = T("Профіль за картами: ", "Profile for these cards: ") + (prof == "" ? why : prof);
            }
            else
            {
                state.ForeColor = Color.DarkGreen;
                state.Text = string.Format(T("Працює: порт {0}, llama.cpp {1}, llama-swap {2}, профіль {3}", "Running: port {0}, llama.cpp {1}, llama-swap {2}, profile {3}"),
                    st["port"], st["llama_cpp"], st["llama_swap"], st["profile"]);
                var run = new List<string>();
                var rr = st["running"] as Dictionary<string, object>;
                if (rr != null && rr.ContainsKey("running"))
                    foreach (Dictionary<string, object> m in (System.Collections.ArrayList)rr["running"]) run.Add(m["model"] + " (" + m["state"] + ")");
                queue.Text = string.Format(T("Зараз: {0} відповідає, {1} у черзі (макс. {2} разом), усього {3}, відмов без токена {4}. Моделі: {5}",
                    "Now: {0} answering, {1} queued (max {2} at once), {3} served, {4} refused without token. Models: {5}"),
                    st["active"], st["waiting"], st["parallel"], st["served"], st["refused"], run.Count == 0 ? T("не завантажені", "none loaded") : string.Join(", ", run));
            }
        }

        void RunSelf(string args, bool elevate)
        {
            var exe = System.Reflection.Assembly.GetExecutingAssembly().Location;
            var outf = Path.Combine(Path.GetTempPath(), "dfir_vao_agent_" + Guid.NewGuid().ToString("N") + ".log");
            var full = args + " --home \"" + Agent.Home + "\"" + (Agent.Uk ? " --lang uk" : " --lang en");
            log.AppendText("> " + args + "\r\n");
            var psi = new ProcessStartInfo("cmd.exe", "/c \"\"" + exe + "\" " + full + " > \"" + outf + "\" 2>&1\"") { CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden };
            if (elevate && !Agent.IsAdmin()) { psi.UseShellExecute = true; psi.Verb = "runas"; } else psi.UseShellExecute = false;
            Process p;
            try { p = Process.Start(psi); }
            catch (Exception e) { log.AppendText(e.Message + "\r\n"); return; }
            long shown = 0;
            var t = new System.Windows.Forms.Timer { Interval = 700 };
            t.Tick += delegate
            {
                try
                {
                    if (File.Exists(outf))
                        using (var f = new FileStream(outf, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        {
                            f.Seek(shown, SeekOrigin.Begin);
                            var txt = new StreamReader(f, System.Text.Encoding.UTF8).ReadToEnd();
                            shown = f.Length;
                            if (txt.Length > 0) log.AppendText(txt.Replace("\r\n", "\n").Replace("\n", "\r\n"));
                        }
                }
                catch { }
                if (p.HasExited) { t.Stop(); log.AppendText(p.ExitCode == 0 ? T("готово\r\n", "done\r\n") : T("помилка, код ", "failed, code ") + p.ExitCode + "\r\n"); Refresh2(); }
            };
            t.Start();
        }

        // test helper: draw the window into a PNG without showing it
        public int Shot(string png)
        {
            StartPosition = FormStartPosition.Manual; Location = new Point(-4000, -4000); ShowInTaskbar = false;
            Show(); Application.DoEvents(); Refresh2(); Application.DoEvents(); timer.Stop();
            using (var b = new Bitmap(Width, Height)) { DrawToBitmap(b, new Rectangle(0, 0, Width, Height)); b.Save(png); }
            Close(); return 0;
        }
    }
}
