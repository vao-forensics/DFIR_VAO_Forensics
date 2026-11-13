// Window of DFIR Collector Builder: one form, one big button. Settings (key, paths) are kept in
// %LOCALAPPDATA%\DFIR_Builder\settings.txt so a rebuild after a tool update is two clicks.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Windows.Forms;

static class BuilderProgram
{
    // a winexe has no console; in --cli mode borrow the one it was started from
    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    static extern bool AttachConsole(int pid);

    [STAThread]
    static int Main(string[] args)
    {
        try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072 | (SecurityProtocolType)12288; }
        catch (NotSupportedException) { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; }

        if (args.Length > 0 && args[0] == "--add-exclusions")
            return Builder.AddExclusionsElevated(args.Skip(1).ToArray());
        if (args.Length > 0 && args[0] == "--cli")
        {
            L.FromSystem();
            int li = Array.IndexOf(args, "--lang");
            if (li > 0 && li + 1 < args.Length) L.En = args[li + 1] != "uk";
            AttachConsole(-1);
            try { Console.OutputEncoding = Encoding.UTF8; } catch (IOException) { }  // no console when output is redirected
            return Cli(args);
        }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        L.FromSystem();
        if (!PickLanguage()) return 0;
        Application.Run(new BuilderForm());
        return 0;
    }

    // first window: English / Ukrainian, the system language is preselected
    static bool PickLanguage()
    {
        var dlg = new Form { Text = "DFIR_VAO_Forensics", FormBorderStyle = FormBorderStyle.FixedDialog,
                             MaximizeBox = false, MinimizeBox = false, StartPosition = FormStartPosition.CenterScreen,
                             ClientSize = new Size(380, 150), Font = new Font("Segoe UI", 10f) };
        var lbl = new Label { Text = "Language / \u041c\u043e\u0432\u0430", AutoSize = true, Location = new Point(20, 18) };
        var en = new RadioButton { Text = "English", AutoSize = true, Location = new Point(24, 50), Checked = L.En };
        var uk = new RadioButton { Text = "\u0423\u043a\u0440\u0430\u0457\u043d\u0441\u044c\u043a\u0430", AutoSize = true,
                                   Location = new Point(160, 50), Checked = !L.En };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(270, 100), Size = new Size(90, 32) };
        dlg.Controls.AddRange(new Control[] { lbl, en, uk, ok });
        dlg.AcceptButton = ok;
        if (dlg.ShowDialog() != DialogResult.OK) return false;
        L.En = en.Checked;
        return true;
    }

    // --cli --seal LINE|@file --kape kape.zip --out DIR [--thor zip --thor-lic lic] [--memory DIR] [--fast-only]
    // --cli --check-tools [--out DIR] [--fast-only]    fetch+verify the newest tools, compile nothing
    // common: [--tools-json FILE] [--mirror URL] [--lang en|uk]
    static int Cli(string[] a)
    {
        var o = new BuildOptions();
        bool checkOnly = false;
        for (int i = 1; i < a.Length; i++)
        {
            string v = i + 1 < a.Length ? a[i + 1] : "";
            switch (a[i])
            {
                case "--seal": o.SealLine = v.StartsWith("@") ? File.ReadAllText(v.Substring(1)).Trim() : v; i++; break;
                case "--kape": o.KapeZip = v; i++; break;
                case "--out": o.OutDir = v; i++; break;
                case "--thor": o.ThorZip = v; i++; break;
                case "--thor-lic": o.ThorLic = v; i++; break;
                case "--memory": o.MemoryDir = v; i++; break;
                case "--fast-only": o.Full = false; break;
                case "--defender-exclusions": o.AddExclusions = true; break;
                case "--lang": i++; break;
                case "--check-tools": checkOnly = true; break;
                case "--tools-json": o.ToolsJson = v; i++; break;
                case "--mirror": o.Mirror = v; i++; break;
                default: Console.Error.WriteLine(L.T("невідомий параметр ", "unknown option ") + a[i]); return 2;
            }
        }
        var b = new Builder(Console.WriteLine, p => { });
        try
        {
            if (checkOnly) Console.WriteLine(b.CheckTools(o));
            else b.Run(o);
            foreach (string w in b.Warnings) Console.WriteLine(L.T("ПОПЕРЕДЖЕННЯ: ", "WARNING: ") + w);
            return b.Warnings.Count == 0 ? 0 : 3;
        }
        catch (BuildFailed e) { Console.Error.WriteLine(L.T("ПОМИЛКА: ", "ERROR: ") + e.Message); return 1; }
    }
}

class BuilderForm : Form
{
    readonly TextBox _seal = new TextBox(), _kape = new TextBox(), _thor = new TextBox(), _thorLic = new TextBox(),
                     _mem = new TextBox(), _out = new TextBox(), _log = new TextBox();
    readonly CheckBox _full = new CheckBox(), _defx = new CheckBox();
    readonly Button _go = new Button();
    readonly ProgressBar _bar = new ProgressBar();
    readonly string _settings = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                             "DFIR_Builder", "settings.txt");

    public BuilderForm()
    {
        Text = "DFIR Collector Builder";
        Font = new Font("Segoe UI", 9.5f);
        ClientSize = new Size(760, 640);
        MinimumSize = new Size(640, 560);
        StartPosition = FormStartPosition.CenterScreen;
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

        var grid = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 3, AutoSize = true, Padding = new Padding(10) };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));

        Row(grid, L.T("Ключ вашого бота", "Your bot's key"), _seal, L.T("З файлу...", "From file..."), PickSeal,
            L.T("Рядок dfir-seal-1:... - install.sh друкує його наприкінці (state/keys/collector_seal.txt).", "The dfir-seal-1:... line - install.sh prints it at the end (state/keys/collector_seal.txt)."));
        Row(grid, "KAPE (kape.zip)", _kape, L.T("Обрати...", "Browse..."), () => PickFile(_kape, "kape.zip|*.zip"),
            null, L.T("Де взяти KAPE", "Where to get KAPE"), "https://www.kroll.com/en/services/cyber/incident-response-recovery/kroll-artifact-parser-and-extractor-kape");
        Row(grid, L.T("THOR Lite (zip), не обов'язково", "THOR Lite (zip), optional"), _thor, L.T("Обрати...", "Browse..."), () => PickFile(_thor, "zip|*.zip"),
            null, L.T("Отримати THOR Lite", "Get THOR Lite"), "https://www.nextron-systems.com/thor-lite/");
        Row(grid, L.T("Ліцензія THOR (.lic)", "THOR licence (.lic)"), _thorLic, L.T("Обрати...", "Browse..."), () => PickFile(_thorLic, "lic|*.lic"));
        Row(grid, L.T("Тека з DumpIt, не обов'язково", "Folder with DumpIt, optional"), _mem, L.T("Обрати...", "Browse..."), () => PickDir(_mem),
            L.T("Потрібна лише для знімка оперативної пам'яті.", "Needed only for a memory (RAM) snapshot."));
        Row(grid, L.T("Куди покласти EXE", "Where to put the EXE"), _out, L.T("Обрати...", "Browse..."), () => PickDir(_out));

        _full.Text = L.T("Повний набір FULL (Chainsaw, RegRipper, Autoruns, DeepBlueCLI...)", "FULL set (Chainsaw, RegRipper, Autoruns, DeepBlueCLI...)");
        _full.Checked = true;
        _full.AutoSize = true;
        grid.Controls.Add(_full, 1, grid.RowCount++);
        _defx.Text = L.T("Додати теки збирача у винятки Defender (один запит прав адміністратора)", "Add the collector folders to Defender exclusions (one administrator prompt)");
        _defx.Checked = true;
        _defx.AutoSize = true;
        grid.Controls.Add(_defx, 1, grid.RowCount++);

        _go.Text = L.T("Докачати все і зібрати збирач", "Download everything and build the collector");
        _go.Height = 44;
        _go.Dock = DockStyle.Top;
        _go.Font = new Font(Font.FontFamily, 11f, FontStyle.Bold);
        _go.Click += (s, e) => Start();
        _bar.Dock = DockStyle.Top;
        _bar.Height = 14;
        _log.Multiline = true;
        _log.ReadOnly = true;
        _log.ScrollBars = ScrollBars.Vertical;
        _log.Dock = DockStyle.Fill;
        _log.Font = new Font("Consolas", 9f);

        var bottom = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10, 0, 10, 10) };
        bottom.Controls.Add(_log);
        bottom.Controls.Add(_bar);
        bottom.Controls.Add(_go);
        Controls.Add(bottom);
        Controls.Add(grid);

        _out.Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "DFIR_Collector");
        Load_();
        FormClosing += (s, e) => Save();
    }

    void Row(TableLayoutPanel g, string label, TextBox box, string btn, Action pick, string hint = null,
             string linkText = null, string url = null)
    {
        int r = g.RowCount++;
        g.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 8, 0, 0) }, 0, r);
        box.Dock = DockStyle.Fill;
        g.Controls.Add(box, 1, r);
        var b = new Button { Text = btn, Dock = DockStyle.Fill };
        b.Click += (s, e) => pick();
        g.Controls.Add(b, 2, r);
        if (hint != null || linkText != null)
        {
            r = g.RowCount++;
            var flow = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0) };
            if (hint != null) flow.Controls.Add(new Label { Text = hint, AutoSize = true, ForeColor = SystemColors.GrayText });
            if (linkText != null)
            {
                var l = new LinkLabel { Text = linkText, AutoSize = true };
                l.LinkClicked += (s, e) => Process.Start(url);
                flow.Controls.Add(l);
            }
            g.Controls.Add(flow, 1, r);
        }
    }

    void PickSeal()
    {
        using (var d = new OpenFileDialog { Filter = "collector_seal.txt|*.txt|*.*|*.*" })
            if (d.ShowDialog(this) == DialogResult.OK) _seal.Text = File.ReadAllText(d.FileName).Trim();
    }

    void PickFile(TextBox t, string filter)
    {
        using (var d = new OpenFileDialog { Filter = filter + "|*.*|*.*" })
            if (d.ShowDialog(this) == DialogResult.OK) t.Text = d.FileName;
    }

    void PickDir(TextBox t)
    {
        using (var d = new FolderBrowserDialog { SelectedPath = t.Text })
            if (d.ShowDialog(this) == DialogResult.OK) t.Text = d.SelectedPath;
    }

    void Start()
    {
        var o = new BuildOptions
        {
            SealLine = _seal.Text.Trim(), KapeZip = _kape.Text.Trim(), ThorZip = _thor.Text.Trim(),
            ThorLic = _thorLic.Text.Trim(), MemoryDir = _mem.Text.Trim(), OutDir = _out.Text.Trim(), Full = _full.Checked,
            AddExclusions = _defx.Checked,
        };
        Save();
        _go.Enabled = false;
        _log.Clear();
        var t = new Thread(() =>
        {
            var b = new Builder(Log, p => BeginInvoke((Action)(() => _bar.Value = Math.Max(0, Math.Min(100, p)))));
            string msg;
            bool ok = false;
            try
            {
                string exe = b.Run(o);
                ok = true;
                msg = L.T("Збирач готовий:\r\n", "Collector ready:\r\n") + exe + (b.Warnings.Count > 0
                    ? L.T("\r\n\r\nНе вдалось отримати (ці кроки будуть порожні):\r\n", "\r\n\r\nCould not get (these steps will be empty):\r\n") + string.Join("\r\n", b.Warnings)
                    : "");
            }
            catch (BuildFailed e) { msg = e.Message; }
            catch (Exception e) { msg = e.ToString(); }
            BeginInvoke((Action)(() =>
            {
                _go.Enabled = true;
                Log(ok ? L.T("ГОТОВО", "DONE") : L.T("ПОМИЛКА: ", "ERROR: ") + msg);
                MessageBox.Show(this, msg, ok ? L.T("Готово", "Done") : L.T("Не вдалось", "Failed"), MessageBoxButtons.OK,
                                ok ? MessageBoxIcon.Information : MessageBoxIcon.Error);
                if (ok) Process.Start("explorer.exe", "\"" + o.OutDir + "\"");
            }));
        }) { IsBackground = true };
        t.Start();
    }

    void Log(string s)
    {
        if (InvokeRequired) { BeginInvoke((Action<string>)Log, s); return; }
        _log.AppendText(s + "\r\n");
    }

    void Load_()
    {
        try
        {
            foreach (string l in File.ReadAllLines(_settings))
            {
                int i = l.IndexOf('=');
                if (i < 0) continue;
                string k = l.Substring(0, i), v = l.Substring(i + 1);
                if (k == "seal") _seal.Text = v;
                else if (k == "kape") _kape.Text = v;
                else if (k == "thor") _thor.Text = v;
                else if (k == "thorlic") _thorLic.Text = v;
                else if (k == "memory") _mem.Text = v;
                else if (k == "out") _out.Text = v;
                else if (k == "full") _full.Checked = v == "1";
                else if (k == "defx") _defx.Checked = v == "1";
            }
        }
        catch { }
    }

    void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_settings));
            File.WriteAllLines(_settings, new[] {
                "seal=" + _seal.Text.Trim(), "kape=" + _kape.Text, "thor=" + _thor.Text, "thorlic=" + _thorLic.Text,
                "memory=" + _mem.Text, "out=" + _out.Text, "full=" + (_full.Checked ? "1" : "0"), "defx=" + (_defx.Checked ? "1" : "0") });
        }
        catch { }
    }
}
