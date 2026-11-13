// Entry point: no arguments = window; CLI for tests and scripts.
//   --detect                                       hypervisors on this PC
//   --create --hv wsl|vmware|hyperv|virtualbox --name N --repo URL|FILE.tar.gz [--dir D] [--ram GB]
//            [--cpus N] [--disk GB] [--agent-home D] [--answers FILE] [--set KEY=VALUE ...]
//            [--ssh-key PUBFILE] [--guest-password P] [--cache D] [--no-start] [--plan] [--test-tg-stub]
//   --user-data --name N [--ssh-key F]              print the cloud-init user-data (check)
//   --seed-iso OUT FILE...                          make a CIDATA ISO from files (check)
//   --status --hv H --name N [--dir D]              guest progress (status file / serial log)
//   --remove --hv H --name N --dir D                delete a VM made by the wizard (marker checked)
//   --keepalive N                                   (autostart) keep a WSL distribution running
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace DfirVao
{
    static class WizardMain
    {
        [DllImport("kernel32.dll")] static extern bool AttachConsole(int pid);

        [STAThread]
        static int Main(string[] args)
        {
            if (args.Length == 0) { Application.EnableVisualStyles(); Application.Run(new WizardForm()); return 0; }
            AttachConsole(-1);
            try { return Cli(args); }
            catch (Exception e) { Console.Error.WriteLine("ERROR: " + (e.InnerException ?? e).Message); return 1; }
        }

        static Spec Parse(string[] a, out string cmd, out List<string> rest)
        {
            var s = new Spec(); cmd = ""; rest = new List<string>();
            for (int i = 0; i < a.Length; i++)
            {
                Func<string> nx = () => a[++i];
                switch (a[i])
                {
                    case "--detect": case "--create": case "--status": case "--remove": case "--user-data": case "--seed-iso": case "--keepalive":
                        cmd = a[i]; if (a[i] == "--keepalive") s.Name = nx(); break;
                    case "--hv": s.Hv = nx(); break;
                    case "--name": s.Name = nx(); break;
                    case "--dir": s.Dir = nx(); break;
                    case "--repo": s.Repo = nx(); break;
                    case "--ref": s.RepoRef = nx(); break;
                    case "--ram": s.RamGb = int.Parse(nx()); break;
                    case "--cpus": s.Cpus = int.Parse(nx()); break;
                    case "--disk": s.DiskGb = int.Parse(nx()); break;
                    case "--agent-home": s.AgentHome = nx(); break;
                    case "--answers": s.AnswersFile = nx(); break;
                    case "--set": var kv = nx(); var p = kv.IndexOf('='); s.Set[kv.Substring(0, p)] = kv.Substring(p + 1); break;
                    case "--ssh-key": s.SshPubKey = File.ReadAllText(nx()).Trim(); break;
                    case "--guest-password": s.GuestPassword = nx(); break;
                    case "--cache": s.CacheDir = nx(); break;
                    case "--no-start": s.Start = false; break;
                    case "--plan": s.PlanOnly = true; break;
                    case "--test-tg-stub": s.TestTgStub = true; break;
                    default: rest.Add(a[i]); break;
                }
            }
            return s;
        }

        static int Cli(string[] args)
        {
            string cmd; List<string> rest;
            var s = Parse(args, out cmd, out rest);
            switch (cmd)
            {
                case "--detect":
                    foreach (var h in Wiz.Detect()) Console.WriteLine("{0}\t{1}\t{2}\t{3}", h.Id, h.Ok ? "ok" : "no", h.Tool ?? "-", h.Note);
                    return 0;
                case "--user-data": Console.Write(Wiz.UserData(s)); return 0;
                case "--seed-iso":
                    Wiz.MakeSeedIso(rest[0], rest.Skip(1).ToDictionary(f => Path.GetFileName(f), f => Path.GetFullPath(f)));
                    Console.WriteLine("ISO " + rest[0]); return 0;
                case "--create":
                    var sum = Wiz.Create(s);
                    Console.WriteLine("DONE " + s.Hv + "/" + s.Name + " in " + s.Dir);
                    foreach (var l in sum) Console.WriteLine("  " + l);
                    return 0;
                case "--status":
                    if (string.IsNullOrEmpty(s.Dir)) s.Dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "DFIR_VAO_VMs", s.Name);
                    Console.WriteLine(Wiz.Status(s)); return 0;
                case "--remove": Wiz.Remove(s); return 0;
                case "--keepalive": Wiz.KeepaliveLoop(s.Name); return 0;
            }
            Console.Error.WriteLine("unknown command; see the header of WizardMain.cs or README.md");
            return 2;
        }
    }

    // The window: what a person needs to fill in; everything else comes from the Host Agent.
    class WizardForm : Form
    {
        readonly bool uk = System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "uk";
        string L(string en, string ua) { return uk ? ua : en; }
        ComboBox hv = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 380 };
        TextBox name = new TextBox { Text = "dfir-vao", Width = 200 }, repo = new TextBox { Width = 380 },
            tg = new TextBox { Width = 380, UseSystemPasswordChar = true }, chat = new TextBox { Width = 200 },
            url = new TextBox { Width = 380 }, email = new TextBox { Text = "admin@dfirbot.com", Width = 260 },
            log = new TextBox { Multiline = true, ScrollBars = ScrollBars.Vertical, ReadOnly = true, Width = 640, Height = 220 };
        NumericUpDown ram = new NumericUpDown { Minimum = 8, Maximum = 512, Value = 16 }, cpus = new NumericUpDown { Minimum = 2, Maximum = 64, Value = 4 },
            disk = new NumericUpDown { Minimum = 80, Maximum = 4000, Value = 200 };
        CheckBox terms = new CheckBox { AutoSize = true };
        Button go = new Button { Width = 160, Height = 32 };

        public WizardForm()
        {
            Text = "DFIR VAO VM Wizard " + Wiz.Version; Width = 700; Height = 720; Font = new Font("Segoe UI", 9);
            var f = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, Padding = new Padding(12), AutoScroll = true, WrapContents = false };
            Action<string, Control> row = (t, c) => { f.Controls.Add(new Label { Text = t, AutoSize = true, Margin = new Padding(0, 8, 0, 0) }); f.Controls.Add(c); };
            row(L("Where the Linux for the bot runs", "Де працюватиме Linux для бота"), hv);
            row(L("Name", "Назва"), name);
            var res = new FlowLayoutPanel { AutoSize = true };
            res.Controls.AddRange(new Control[] { new Label { Text = "RAM GB", AutoSize = true }, ram, new Label { Text = "CPU", AutoSize = true }, cpus, new Label { Text = L("Disk GB", "Диск ГБ"), AutoSize = true }, disk });
            f.Controls.Add(res);
            row(L("Project: git URL or .tar.gz", "Проєкт: git-адреса або .tar.gz"), repo);
            row(L("Telegram bot token (from @BotFather)", "Токен Telegram-бота (від @BotFather)"), tg);
            row(L("Your Telegram chat_id (owner)", "Ваш chat_id у Telegram (власник)"), chat);
            row(L("Public HTTPS address Telegram reaches the bot at", "Публічна HTTPS-адреса, на яку Telegram стукає до бота"), url);
            row(L("Web admin e-mail (passwords are generated and shown at the end)", "Пошта адміна веб-частин (паролі згенеруються й покажуться в кінці)"), email);
            terms.Text = L("I accept the licence terms of the project and of the third-party tools (README)", "Приймаю умови ліцензії проєкту й сторонніх інструментів (README)");
            f.Controls.Add(terms);
            go.Text = L("Create and install", "Створити й встановити"); f.Controls.Add(go);
            f.Controls.Add(log);
            Controls.Add(f);
            Wiz.Log = m => BeginInvoke((Action)(() => log.AppendText(m + Environment.NewLine)));
            Load += (o, e) => new Thread(() =>
            {
                var l = Wiz.Detect();
                var ag = Wiz.ReadAgent(null);
                BeginInvoke((Action)(() =>
                {
                    foreach (var h in l) hv.Items.Add(h);
                    hv.SelectedItem = l.FirstOrDefault(h => h.Ok) ?? l[0];
                    log.AppendText(ag == null ? L("No DFIR VAO Host Agent on this PC: install it first (it serves the AI).\r\n", "На цьому ПК нема DFIR VAO Host Agent: спершу встановіть його (він дає ШІ).\r\n")
                                              : L("Host Agent found, port ", "Агент хоста знайдено, порт ") + ag.Port + "\r\n");
                }));
            }) { IsBackground = true }.Start();
            go.Click += (o, e) =>
            {
                var h = hv.SelectedItem as Hv;
                if (h == null || !h.Ok) { MessageBox.Show(L("This hypervisor is not ready: ", "Цей гіпервізор не готовий: ") + (h == null ? "" : h.Note)); return; }
                if (!terms.Checked) { MessageBox.Show(L("Accept the licence terms first.", "Спершу прийміть умови ліцензії.")); return; }
                var s = new Spec { Hv = h.Id, Name = name.Text.Trim(), Repo = repo.Text.Trim(), RamGb = (int)ram.Value, Cpus = (int)cpus.Value, DiskGb = (int)disk.Value };
                s.Set["INSTALL_LANG"] = uk ? "uk" : "en"; s.Set["BOT_LANG"] = uk ? "uk" : "en"; s.Set["ACCEPT_TERMS"] = "yes";
                s.Set["DFIR_TG_BOT_TOKEN"] = tg.Text.Trim(); s.Set["OWNER_CHAT_ID"] = chat.Text.Trim();
                s.Set["TUNNEL"] = "url"; s.Set["NGROK_URL"] = url.Text.Trim(); s.Set["WEBUI_ADMIN_EMAIL"] = email.Text.Trim();
                go.Enabled = false;
                new Thread(() =>
                {
                    try
                    {
                        var sum = Wiz.Create(s);
                        Wiz.Log(L("DONE. Write these down:", "ГОТОВО. Запишіть:"));
                        foreach (var l in sum) Wiz.Log("  " + l);
                        if (s.Hv != "wsl") Wiz.Log(L("The install goes on inside the VM (30-90 min). Progress: ", "Встановлення триває всередині ВМ (30-90 хв). Хід: ") + "--status --hv " + s.Hv + " --name " + s.Name);
                    }
                    catch (Exception x) { Wiz.Log("ERROR: " + (x.InnerException ?? x).Message); }
                    BeginInvoke((Action)(() => go.Enabled = true));
                }) { IsBackground = true }.Start();
            };
        }
    }
}
