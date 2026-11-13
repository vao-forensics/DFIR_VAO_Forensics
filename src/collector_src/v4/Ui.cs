// Console, banner, menus, progress. Everything the .bat used to draw with echo.
//
// WHY THIS EXISTS AT ALL (2026-08-13): on a ransomware-hit host the collector died because
// Group Policy forbids running .ps1 FILES, and our -ExecutionPolicy Bypass cannot override a
// policy-scoped setting. Every screen the operator saw came from a .bat calling PowerShell.
// v4 draws its own screens from managed code, so no shell is in the path.

using System;
using System.Collections.Generic;
using System.Text;

static class Ui
{
    public const int W = 108;          // rule width, matches the v3 layout the owner approved
    // Bumped whenever the shipped exe changes in a way an operator would notice. The date is
    // read off the start screen when a case is disputed, so a stale one here is a false
    // statement about which tool touched the machine.
    public const string VER = "v4.10 (2026-10-23)";

    public static string Bar(char c) { return "  " + new string(c, W); }

    public static void Setup()
    {
        try
        {
            // CP1251 covers Ukrainian i/i/ie/g and is what every earlier build rendered
            // correctly on real consoles. When output is redirected there is no console font
            // to satisfy, and cp1251 bytes come back as mojibake in the captured log - which
            // made the first unattended run's log unreadable - so use UTF-8 there.
            bool redirected;
            try { redirected = Console.IsOutputRedirected; } catch { redirected = true; }
            Console.OutputEncoding = redirected ? (Encoding)new UTF8Encoding(false)
                                                : Encoding.GetEncoding(1251);
            if (!redirected) Console.InputEncoding = Encoding.GetEncoding(1251);
        }
        catch { }
        try
        {
            int w = Math.Min(120, Console.LargestWindowWidth);
            int h = Math.Min(52, Console.LargestWindowHeight);
            Console.SetWindowSize(Math.Min(80, w), Math.Min(25, h)); // shrink before buffer
            Console.SetBufferSize(w, 4000);
            Console.SetWindowSize(w, h);
        }
        catch { }
        try
        {
            // QuickEdit: one stray click freezes all output until a key is pressed. The
            // operator reads that as "it hung" and kills the collection mid-run.
            Native.DisableQuickEdit();
        }
        catch { }
        try { Console.Title = "DFIR Triage Collector " + VER; } catch { }
        try
        {
            Console.BackgroundColor = ConsoleColor.Black;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Clear();
        }
        catch { }
    }

    public static void Banner()
    {
        Console.WriteLine();
        Console.WriteLine(Bar('='));
        Console.WriteLine("    db    db  .d8b.   .d88b.        d8888b. d88888b d888888b d8888b.      D F I R   T R I A G E");
        Console.WriteLine("    88    88 d8' `8b .8P  Y8.       88  `8D 88'       `88'   88  `8D      C O L L E C T O R");
        Console.WriteLine("    Y8    8P 88ooo88 88    88       88   88 88ooo      88    88oobY'");
        Console.WriteLine("    `8b  d8' 88~~~88 88    88       88   88 88~~~      88    88`8b        версія   " + VER);
        Console.WriteLine("     `8bd8'  88   88 `8b  d8'       88  .8D 88        .88.   88 `88.      автор    V . A . O");
        Console.WriteLine("      `88'   YP   YP  `Y88P'        Y8888D' YP      Y888888P 88   YD      профіль  digital forensics");
        Console.WriteLine();
        Console.WriteLine("    collect  .  parse  .  hunt                                            пошта    github.com/vao-forensics");
        Console.WriteLine("    артефакти -> ZIP -> бот -> звіт від локальної ЛЛМ, без інтернету      бот      t.me/<your_bot>");
        Console.WriteLine(Bar('='));
    }

    public static void Section(string title)
    {
        Console.WriteLine();
        Console.WriteLine(Bar('-'));
        Console.WriteLine("   " + title);
        Console.WriteLine(Bar('-'));
    }

    /// <summary>Coloured status line inside a panel: label, value, and a severity tint.</summary>
    public static void Field(string label, string value, Sev sev)
    {
        Console.Write("      " + label.PadRight(18) + " : ");
        Write(value, sev);
        Console.WriteLine();
    }

    public enum Sev { Plain, Good, Warn, Bad, Unknown }

    public static void Write(string s, Sev sev)
    {
        ConsoleColor old = Console.ForegroundColor;
        try
        {
            switch (sev)
            {
                case Sev.Good: Console.ForegroundColor = ConsoleColor.Green; break;
                case Sev.Warn: Console.ForegroundColor = ConsoleColor.Yellow; break;
                case Sev.Bad: Console.ForegroundColor = ConsoleColor.Red; break;
                case Sev.Unknown: Console.ForegroundColor = ConsoleColor.DarkGray; break;
            }
            Console.Write(s);
        }
        finally { Console.ForegroundColor = old; }
    }

    public static void Line(string s, Sev sev) { Write(s, sev); Console.WriteLine(); }

    public static void Note(string s) { Console.WriteLine("      " + s); }

    // ---- persistent header -------------------------------------------------------
    // The start screen is taller than a console, so as questions accumulate the earlier ones
    // scroll away - the owner's long-standing complaint that "the terminal cuts information
    // off". Each question therefore redraws on a clean screen, with a compact header that
    // keeps the two things the operator must not forget: the machine's state and the answers
    // already given.

    public static List<string> Crumbs = new List<string>();
    public static string Status = "";
    public static Sev StatusSev = Sev.Plain;
    public static bool ClearBeforeQuestion;

    public static void Screen()
    {
        try { Console.Clear(); } catch { }
        Console.WriteLine();
        Console.WriteLine(Bar('='));
        Console.WriteLine("   D F I R   T R I A G E   C O L L E C T O R      " + VER
                          + "      V . A . O");
        if (Status.Length > 0)
        {
            Console.Write("   ");
            Line(Status, StatusSev);
        }
        if (Crumbs.Count > 0)
            Console.WriteLine("   обрано:  " + string.Join("   |   ", Crumbs.ToArray()));
        Console.WriteLine(Bar('='));
    }

    public static void Crumb(string s) { Crumbs.Add(s); }

    /// <summary>
    /// One menu question. Returns the chosen key. Unlike the .bat version this NEVER loops
    /// forever: the bat's drive prompt had no attempt limit, and on the failing host the
    /// operator was trapped in it.
    /// </summary>
    public static string Ask(string title, string[] keys, string[] texts, string def)
    {
        if (ClearBeforeQuestion) Screen();
        Section(title);
        for (int i = 0; i < keys.Length; i++)
        {
            string[] parts = texts[i].Split('\n');
            Console.WriteLine("     [" + keys[i] + "] " + parts[0]);
            for (int j = 1; j < parts.Length; j++)
                Console.WriteLine("         " + parts[j]);
        }
        Console.WriteLine();
        for (int attempt = 0; attempt < 5; attempt++)
        {
            Console.Write("   Вибір [" + string.Join("/", keys) + ", за замовч. " + def + "]: ");
            string a = ReadLine();
            a = (a == null) ? "" : a.Trim();
            if (a.Length == 0) return def;
            foreach (string k in keys) if (string.Equals(a, k, StringComparison.OrdinalIgnoreCase)) return k;
            Line("   Немає такого пункту. Оберіть одне з: " + string.Join(", ", keys), Sev.Warn);
        }
        Line("   Забагато невдалих спроб - беру значення за замовчуванням: " + def, Sev.Warn);
        return def;
    }

    /// <summary>Free-text prompt with a default and a hard attempt limit.</summary>
    public static string AskText(string prompt, string def)
    {
        Console.Write("   " + prompt
            + (string.IsNullOrEmpty(def) ? "" : " [" + def + "]") + ": ");
        string a = ReadLine();
        a = (a == null) ? "" : a.Trim();
        return a.Length == 0 ? def : a;
    }

    public static string ReadLine()
    {
        try { return Console.ReadLine(); }
        catch { return null; }
    }

    /// <summary>Set for unattended runs so a regression test cannot block on a prompt.</summary>
    public static bool Unattended;

    public static void Pause(string msg)
    {
        Console.WriteLine();
        if (Unattended) { Console.WriteLine("  " + msg + " (авто)"); return; }
        Console.Write("  " + msg);
        try { Console.ReadLine(); } catch { }
    }

    // ---- progress ----------------------------------------------------------------
    // 2026-09-05: the \r spinner is gone. It looked alive, but it told the operator nothing
    // about how long to wait, and the moment the console was resized the rewritten line
    // "floated" across the screen (the owner's words). Progress is now APPEND-ONLY: a line
    // when a step starts (with the expected duration), a heartbeat line every 30 s while it
    // runs (elapsed / expected, and the last thing the tool said), and a line when it ends.
    // Nothing on the screen is ever rewritten, so a resize just re-flows text.

    const int HEARTBEAT_S = 30;

    public static void ProgressStart(string phase, string label, TimeSpan expected)
    {
        string exp = expected.TotalSeconds > 0 ? "  очік. ~" + Short(expected) : "";
        Console.WriteLine(string.Format("   [{0}] {1}  почато {2:HH:mm:ss}{3}",
            phase, label, DateTime.Now, exp));
        TimeSpan total = Eta.Remaining();
        if (total.TotalSeconds > 0)
            Console.WriteLine("        до кінця збору ~" + Short(total)
                              + "  (орієнтовно " + DateTime.Now.Add(total).ToString("HH:mm") + ")");
    }

    /// <summary>Called by the runner every 250 ms; prints only on the heartbeat boundary.</summary>
    public static void ProgressBeat(string phase, TimeSpan el, TimeSpan expected, string last,
                                    ref int lastBeat)
    {
        int beat = (int)(el.TotalSeconds / HEARTBEAT_S);
        if (beat == lastBeat) return;
        lastBeat = beat;
        string tail = last ?? "";
        if (tail.Length > 60) tail = tail.Substring(tail.Length - 60);
        string exp = expected.TotalSeconds > 0 ? " / ~" + Short(expected) : "";
        Console.WriteLine(string.Format("        ... [{0}] триває {1}{2}{3}", phase, Short(el), exp,
            tail.Length > 0 ? "   " + tail : ""));
    }

    public static void ProgressDone(string phase, string label, TimeSpan el, bool ok)
    {
        Console.Write("   ");
        Write(ok ? "[OK]" : "[!]", ok ? Sev.Good : Sev.Bad);
        Console.WriteLine(string.Format(" [{0}] {1} - {2}", phase, label, Short(el)));
    }

    /// <summary>"2 хв 15 с" / "45 с" / "1 год 03 хв" - what an operator reads at a glance.</summary>
    public static string Short(TimeSpan t)
    {
        if (t.TotalSeconds < 0) t = TimeSpan.Zero;
        if (t.TotalHours >= 1) return string.Format("{0} год {1:00} хв", (int)t.TotalHours, t.Minutes);
        if (t.TotalMinutes >= 1) return string.Format("{0} хв {1:00} с", (int)t.TotalMinutes, t.Seconds);
        return string.Format("{0} с", (int)t.TotalSeconds);
    }

    public static string Trunc(string s, int n)
    {
        if (s == null) return "";
        return s.Length <= n ? s.PadRight(n) : s.Substring(0, n);
    }

    public static string Gb(long bytes)
    {
        return (bytes / 1073741824.0).ToString("0.0");
    }

    public static List<string> Wrap(string text, int width)
    {
        List<string> outp = new List<string>();
        foreach (string para in text.Split('\n'))
        {
            string cur = "";
            foreach (string word in para.Split(' '))
            {
                if (cur.Length == 0) { cur = word; }
                else if (cur.Length + 1 + word.Length <= width) { cur += " " + word; }
                else { outp.Add(cur); cur = word; }
            }
            outp.Add(cur);
        }
        return outp;
    }
}
