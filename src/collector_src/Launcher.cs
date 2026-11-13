// DFIR collector launcher - ask first, extract only what the answer needs.
//
// WHY NATIVE AND NOT PYTHON (measured 2026-08-09):
//   * with the payload bundled as a PyInstaller data file, PyInstaller unpacked 670 MB into
//     %TEMP%\_MEI before our code even started, then we extracted another 1.09 GB - roughly
//     1.76 GB written per run, most of it never used;
//   * appending the payload to a PyInstaller onefile exe is impossible: its bootloader locates
//     its own archive from the END of the file, so an overlay breaks it outright
//     ("ImportError: Cannot load frozen modules" - verified, not assumed).
// A plain .NET console exe has neither problem: ~15 KB, starts instantly, and reading an
// overlay out of its own file is a normal seek.
//
// Layout of the shipped exe:  [ PE ][ uncompressed zip ][ int64 zip offset ][ "DFIRPAY1" ]
// The zip is STORED (no compression), so extracting a tier is a plain disk copy.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;

// A read-only window onto part of another stream. ZipArchive reads the end-of-central-directory
// from the stream's end, so it must not see the PE in front or the footer behind.
class SubStream : Stream
{
    private readonly Stream _base;
    private readonly long _off, _len;
    private long _pos;

    public SubStream(Stream b, long off, long len) { _base = b; _off = off; _len = len; _pos = 0; }

    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return true; } }
    public override bool CanWrite { get { return false; } }
    public override long Length { get { return _len; } }
    public override long Position
    {
        get { return _pos; }
        set { _pos = value; _base.Position = _off + value; }
    }
    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_pos >= _len) return 0;
        if (count > _len - _pos) count = (int)(_len - _pos);
        _base.Position = _off + _pos;
        int n = _base.Read(buffer, offset, count);
        _pos += n;
        return n;
    }
    public override long Seek(long offset, SeekOrigin origin)
    {
        long t = origin == SeekOrigin.Begin ? offset
               : origin == SeekOrigin.Current ? _pos + offset : _len + offset;
        Position = t;
        return _pos;
    }
    public override void SetLength(long value) { throw new NotSupportedException(); }
    public override void Write(byte[] b, int o, int c) { throw new NotSupportedException(); }
}

static class Launcher
{
    const string MAGIC = "DFIRPAY1";
    const string VER = "v3.0 (2026-08-09)";

    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int h);
    [DllImport("kernel32.dll")] static extern bool GetConsoleMode(IntPtr h, out uint m);
    [DllImport("kernel32.dll")] static extern bool SetConsoleMode(IntPtr h, uint m);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern bool SetFileAttributesW(string path, uint attrs);

    static void SetupConsole()
    {
        try
        {
            Console.OutputEncoding = Encoding.GetEncoding(1251); // same code page as the .bat
            Console.InputEncoding = Encoding.GetEncoding(1251);
        }
        catch { }
        try
        {
            int w = Math.Min(120, Console.LargestWindowWidth);
            int h = Math.Min(50, Console.LargestWindowHeight);
            Console.SetWindowSize(Math.Min(80, w), Math.Min(25, h)); // shrink before resizing buffer
            Console.SetBufferSize(w, 3000);
            Console.SetWindowSize(w, h);
        }
        catch { }
        try
        {
            // QuickEdit on: one stray click freezes all output until a key is pressed
            IntPtr hIn = GetStdHandle(-10);
            uint mode;
            if (GetConsoleMode(hIn, out mode))
                SetConsoleMode(hIn, (mode & ~0x0040u) | 0x0080u);
        }
        catch { }
        try { Console.Title = "DFIR Triage Collector " + VER; } catch { }
    }

    static void Banner()
    {
        string bar = "  " + new string('=', 108);
        Console.WriteLine();
        Console.WriteLine(bar);
        Console.WriteLine("    db    db  .d8b.   .d88b.        d8888b. d88888b d888888b d8888b.      D F I R   T R I A G E");
        Console.WriteLine("    88    88 d8' `8b .8P  Y8.       88  `8D 88'       `88'   88  `8D      C O L L E C T O R");
        Console.WriteLine("    Y8    8P 88ooo88 88    88       88   88 88ooo      88    88oobY'");
        Console.WriteLine("    `8b  d8' 88~~~88 88    88       88   88 88~~~      88    88`8b        версія   " + VER);
        Console.WriteLine("     `8bd8'  88   88 `8b  d8'       88  .8D 88        .88.   88 `88.      автор    V . A . O");
        Console.WriteLine("      `88'   YP   YP  `Y88P'        Y8888D' YP      Y888888P 88   YD      профіль  digital forensics");
        Console.WriteLine();
        Console.WriteLine("    collect  .  parse  .  hunt                                            пошта    github.com/vao-forensics");
        Console.WriteLine("    артефакти -> ZIP -> бот -> звіт від локальної ЛЛМ, без інтернету      бот      t.me/<your_bot>");
        Console.WriteLine(bar);
    }

    static string Ask(string title, string[] keys, string[] texts, string def)
    {
        string bar = "  " + new string('-', 108);
        Console.WriteLine();
        Console.WriteLine(bar);
        Console.WriteLine("   " + title);
        Console.WriteLine(bar);
        for (int i = 0; i < keys.Length; i++)
            Console.WriteLine("     [" + keys[i] + "] " + texts[i]);
        Console.WriteLine();
        Console.Write("   Вибір [" + string.Join("/", keys) + ", за замовч. " + def + "]: ");
        string a = Console.ReadLine();
        a = (a == null) ? "" : a.Trim();
        foreach (string k in keys) if (a == k) return a;
        return def;
    }

    static bool ReadFooter(string me, out long off)
    {
        off = 0;
        try
        {
            using (FileStream fs = new FileStream(me, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                if (fs.Length < 32) return false;
                fs.Position = fs.Length - 16;
                byte[] tail = new byte[16];
                if (fs.Read(tail, 0, 16) != 16) return false;
                if (Encoding.ASCII.GetString(tail, 8, 8) != MAGIC) return false;
                off = BitConverter.ToInt64(tail, 0);
                return off > 0 && off < fs.Length - 16;
            }
        }
        catch { return false; }
    }

    static int Fail(string msg)
    {
        Console.WriteLine();
        Console.WriteLine("  [X] " + msg);
        Console.Write("  Enter для виходу...");
        try { Console.ReadLine(); } catch { }
        return 1;
    }

    static void KillDir(string dir)
    {
        for (int i = 0; i < 5; i++)
        {
            try { Directory.Delete(dir, true); return; }
            catch { System.Threading.Thread.Sleep(700); }
        }
    }

    static int Main(string[] argv)
    {
        SetupConsole();
        Banner();

        string me = Process.GetCurrentProcess().MainModule.FileName;
        long off;
        if (!ReadFooter(me, out off))
            return Fail("Пошкоджений файл: службові дані не знайдено. Завантажте збирач ще раз.");

        string scen = Ask("[ 1 ]  РЕЖИМ ЗБОРУ",
            new string[] { "1", "2" },
            new string[] { "LIVE   - жива система, що працює зараз",
                           "IMAGE  - змонтований образ диска (офлайн)" }, "1");
        string mode = Ask("[ 2 ]  ГЛИБИНА",
            new string[] { "1", "2" },
            new string[] { "FAST - швидко (хвилини): артефакти + типовий розбір",
                           "FULL - глибоко: додатково sigma-полювання, THOR, реєстр" }, "1");

        // Recognisable prefix on purpose: the .bat must be able to tell ITS OWN leftover
        // Defender exclusions from anyone else's, because on a target machine a stale
        // exclusion is evidence and must never be cleaned up blindly.
        string work = Path.Combine(Path.GetTempPath(),
            "DFIRTriage_" + Guid.NewGuid().ToString("N").Substring(0, 10));
        Directory.CreateDirectory(work);
        try { SetFileAttributesW(work, 0x2); } catch { }

        Console.WriteLine();
        Console.WriteLine("  " + new string('-', 108));
        Console.WriteLine("   Розпаковується ЛИШЕ те, що потрібно обраному режиму - решта лишається всередині файла.");
        Console.WriteLine("  " + new string('-', 108));

        int extracted = 0;
        long bytes = 0;
        Stopwatch sw = Stopwatch.StartNew();
        try
        {
            using (FileStream fs = new FileStream(me, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (SubStream sub = new SubStream(fs, off, fs.Length - 16 - off))
            using (ZipArchive zip = new ZipArchive(sub, ZipArchiveMode.Read))
            {
                ZipArchiveEntry man = zip.GetEntry("_tiers.txt");
                if (man == null) return Fail("Пошкоджений файл: немає опису складу. Завантажте збирач ще раз.");

                List<string> want = new List<string>();
                using (StreamReader rd = new StreamReader(man.Open(), Encoding.UTF8))
                {
                    string line;
                    while ((line = rd.ReadLine()) != null)
                    {
                        int t = line.IndexOf('\t');
                        if (t <= 0) continue;
                        string tier = line.Substring(0, t);
                        if (tier == "core" || tier == "fast" || (tier == "full" && mode == "2"))
                            want.Add(line.Substring(t + 1));
                    }
                }

                int total = want.Count;
                foreach (string name in want)
                {
                    ZipArchiveEntry e = zip.GetEntry(name);
                    if (e == null) continue;
                    string dest = Path.Combine(work, name.Replace('/', '\\'));
                    string d = Path.GetDirectoryName(dest);
                    if (!Directory.Exists(d)) Directory.CreateDirectory(d);
                    try { e.ExtractToFile(dest, true); bytes += e.Length; }
                    catch { continue; }
                    extracted++;
                    if (extracted % 250 == 0 || extracted == total)
                    {
                        int pct = total > 0 ? (int)(extracted * 100L / total) : 100;
                        Console.Write("\r     розпакування         [" + new string('#', pct / 4)
                            + new string('.', 25 - pct / 4) + "] " + pct.ToString().PadLeft(3)
                            + "%  " + extracted + "/" + total + "   ");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            KillDir(work);
            return Fail("Не вдалося розпакувати: " + ex.Message);
        }
        sw.Stop();
        Console.WriteLine();
        Console.WriteLine("     готово: " + extracted + " файлів, "
            + (bytes / 1048576).ToString() + " МБ, за "
            + sw.Elapsed.TotalSeconds.ToString("0.0") + " с");

        string bat = Path.Combine(work, "Run_KAPE_DFIR.bat");
        if (!File.Exists(bat))
        {
            KillDir(work);
            return Fail("Не знайдено керуючий сценарій. Завантажте збирач ще раз.");
        }

        try
        {
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c \"" + bat + "\"");
            psi.UseShellExecute = false;
            psi.WorkingDirectory = work;
            psi.EnvironmentVariables["DFIR_SCEN"] = scen; // the .bat skips its own two questions
            psi.EnvironmentVariables["DFIR_MODE"] = mode;
            psi.EnvironmentVariables["DFIR_VER"] = VER;
            Process p = Process.Start(psi);
            p.WaitForExit();
        }
        catch (Exception ex)
        {
            KillDir(work);
            return Fail("Не вдалося запустити збір: " + ex.Message);
        }

        KillDir(work);
        return 0;
    }
}
