// Memory acquisition. LIVE only - enforced by the caller and stated again here, because on a
// mounted image there is no suspect RAM and a capture would grab the EXAMINER's memory.
//
// Tool choice (owner's decision 2026-08-13): Magnet DumpIt. It is signed, fast, and writes a
// Microsoft crash dump that Volatility 3 reads directly. It is NOT redistributable without
// checking Magnet's terms, and it is not in the toolkit yet, so this module locates a capture
// binary at run time and says plainly what is missing when it cannot find one.
//
// Rejected alternatives, recorded so nobody re-treads them:
//   WinPmem - current drivers are UNSIGNED; using them needs testsigning + a REBOOT of the
//             victim machine, which is forensically unacceptable.
//   writing our own physical-memory reader - naive reads walk into MMIO ranges and hang or
//             bugcheck the box. Real tools call MmGetPhysicalMemoryRanges. We will not
//             reimplement that on someone else's evidence.
//
// The dump NEVER goes into the case archive: it is the size of RAM. Only a small manifest
// travels to the bot, plus (mode 4) targeted process dumps.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

static class Memory
{
    // Names we accept, in preference order. DumpIt first per the owner's decision.
    static readonly string[] ToolNames = {
        "DumpIt.exe", "DumpIt64.exe", "MagnetRAMCapture.exe", "RamCapture64.exe",
        "RamCapture.exe", "winpmem.exe"
    };

    /// <summary>Look in the extracted toolkit first, then next to the collector exe.</summary>
    public static string FindTool(string tool)
    {
        List<string> dirs = new List<string>();
        dirs.Add(Path.Combine(tool, @"Modules\bin"));
        dirs.Add(Path.Combine(tool, @"Modules\bin\memory"));
        try { dirs.Add(Path.GetDirectoryName(Payload.SelfPath)); } catch { }
        foreach (string d in dirs)
        {
            if (d == null || !Directory.Exists(d)) continue;
            foreach (string n in ToolNames)
            {
                string p = Path.Combine(d, n);
                if (File.Exists(p)) return p;
            }
        }
        return null;
    }

    /// <summary>
    /// How much the "memory files" option will actually add. Measured from the target drive,
    /// so it is right for a mounted image too. On a 128 GB machine this is tens of gigabytes -
    /// the operator has to see that before choosing, not discover it during an hour-long zip.
    /// </summary>
    public static long EstimateFilesBytes(string drive, long ramBytes)
    {
        long total = 0;
        bool sawAny = false;
        foreach (string n in new string[] { "pagefile.sys", "swapfile.sys", "hiberfil.sys" })
        {
            try
            {
                FileInfo fi = new FileInfo(drive + @":\" + n);
                if (fi.Exists) { total += fi.Length; sawAny = true; }
            }
            catch { }
        }
        if (sawAny && total > 0) return total;

        // The page file is often unreadable as a plain file; WMI still reports its size.
        try
        {
            using (System.Management.ManagementObjectSearcher s =
                new System.Management.ManagementObjectSearcher(
                    "SELECT AllocatedBaseSize FROM Win32_PageFileUsage"))
                foreach (System.Management.ManagementObject m in s.Get())
                    total += Convert.ToInt64(m["AllocatedBaseSize"]) * 1048576L;
        }
        catch { }
        return total;
    }

    /// <summary>
    /// What each acquisition tool actually needs - established by reading the binary, not by
    /// guessing. DumpIt v1.3.2 (MoonSols, 2011) has NO /O and NO /Q switch: it writes
    /// "COMPUTERNAME-YYYYMMDD-HHMMSS.raw" into the CURRENT DIRECTORY and first asks
    /// "Are you sure you want to continue? [y/n]". An earlier version of this file passed it
    /// "/O path /Q", which it would have ignored - the image would have landed in the
    /// collector's own temp folder and been deleted along with it.
    /// </summary>
    static bool IsDumpIt(string exe)
    {
        return Path.GetFileName(exe).ToLowerInvariant().StartsWith("dumpit");
    }

    /// <summary>
    /// Full RAM capture. Returns the manifest rows to write into the case, and never throws:
    /// a failed capture must still leave a usable triage archive behind.
    /// </summary>
    public static string CaptureFull(string tool, string dest, string caseName, string outDir,
                                     long ramBytes, Action<string, string> gap)
    {
        Directory.CreateDirectory(Path.Combine(outDir, "memory"));
        string manifest = Path.Combine(outDir, @"memory\ram_capture.csv");

        string exe = FindTool(tool);
        if (exe == null)
        {
            Ui.Line("      [X] Інструмент захоплення пам'яті не знайдено.", Ui.Sev.Bad);
            Ui.Note("          Покладіть DumpIt.exe поруч із цим файлом збирача і запустіть ще раз.");
            Ui.Note("          Завантаження: magnetforensics.com, розділ безкоштовних інструментів.");
            gap("дамп оперативної пам'яті", "не знайдено інструмент захоплення (DumpIt.exe)");
            Write(manifest, new string[][] {
                new string[] { "status", "tool_missing", "", "", "" } });
            return null;
        }

        string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string outFile = Path.Combine(dest, caseName + "_" + stamp + ".dmp");
        long free = Drives.FreeOn(dest);
        long need = (ramBytes > 0 ? ramBytes : 8L * 1073741824L) + 1073741824L;
        if (free >= 0 && free < need)
        {
            Ui.Line("      [X] На " + dest + " бракує місця: потрібно ~" + Ui.Gb(need)
                    + " ГБ, вільно " + Ui.Gb(free) + " ГБ.", Ui.Sev.Bad);
            gap("дамп оперативної пам'яті", "замало місця на " + dest);
            Write(manifest, new string[][] {
                new string[] { "status", "no_space", dest, Ui.Gb(free), Ui.Gb(need) } });
            return null;
        }

        Console.WriteLine();
        Ui.Line("      [!] Починаю захоплення пам'яті. Не вимикайте і не блокуйте машину.",
                Ui.Sev.Warn);
        Ui.Note("          Інструмент: " + Path.GetFileName(exe));
        Ui.Note("          Файл: " + outFile);
        Ui.Note("          Ризик синього екрана малий, але не нульовий - тріаж уже зібрано.");

        // WATCHDOG (2026-09-05). A field run hung here in a loop with no way out: the capture
        // tool never returned and the collector had given it no timeout at all. Now:
        //   * the expected time is RAM / 50 MB/s (what DumpIt sustains on a SATA disk), and
        //     the hard timeout is three times that plus ten minutes - never below 20 min;
        //   * the dump file on disk is watched; if it has not grown for 4 minutes the tool
        //     is killed, because a healthy capture writes continuously;
        //   * one retry with explicit switches (the Magnet build understands /O and /Q; the
        //     2011 MoonSols build ignores them and still answers the prompt from stdin);
        //   * whatever happens, the step ends and the triage archive is still produced.
        double expectSec = Math.Max(120, (ramBytes > 0 ? ramBytes : 8L * 1073741824L) / (50.0 * 1048576));
        Eta.Expect("RAM", expectSec);
        int timeoutMs = (int)Math.Min(int.MaxValue / 2, Math.Max(20 * 60, expectSec * 3 + 600) * 1000);
        const int STALL_MS = 4 * 60 * 1000;
        string watchDir = dest;
        DateTime t0 = DateTime.Now;
        Runner.Watch growth = delegate ()
        {
            // the tool may name the file itself: watch the newest big file in the folder
            long best = -1;
            try
            {
                if (File.Exists(outFile)) return new FileInfo(outFile).Length;
                foreach (string f in Directory.GetFiles(watchDir))
                {
                    FileInfo fi = new FileInfo(f);
                    if (fi.LastWriteTime >= t0.AddSeconds(-5) && fi.Length > best) best = fi.Length;
                }
            }
            catch { }
            return best;
        };

        int rc;
        if (IsDumpIt(exe))
        {
            // Working directory IS the destination, and "y" answers the confirmation prompt.
            rc = Runner.Run(exe, "", dest, null, "RAM",
                            "Захоплення оперативної пам'яті", timeoutMs, "y\r\n", growth, STALL_MS);
        }
        else
        {
            rc = Runner.Run(exe, "\"" + outFile + "\"", Path.GetDirectoryName(exe), null,
                            "RAM", "Захоплення оперативної пам'яті", timeoutMs, null, growth, STALL_MS);
        }
        DateTime t1 = DateTime.Now;

        long size = Newest(dest, outFile, t0, ref outFile);

        if (size <= 0 && IsDumpIt(exe))
        {
            Ui.Line("      [!] Перша спроба не дала файла (код " + rc + ") - пробую ще раз з явними ключами.", Ui.Sev.Warn);
            Ui.Note("          Якщо і це не спрацює, збір продовжиться без дампа.");
            try { if (File.Exists(outFile)) File.Delete(outFile); } catch { }
            t0 = DateTime.Now;
            rc = Runner.Run(exe, "/O \"" + outFile + "\" /Q", dest, null, "RAM",
                            "Захоплення оперативної пам'яті (спроба 2)", timeoutMs, "y\r\n", growth, STALL_MS);
            t1 = DateTime.Now;
            size = Newest(dest, outFile, t0, ref outFile);
        }

        if (size <= 0)
        {
            Ui.Line("      [X] Дамп не створено (код " + rc + ").", Ui.Sev.Bad);
            if (rc == -2) Ui.Note("          Перевищено час очікування - інструмент зупинено.");
            if (rc == -3) Ui.Note("          Файл дампа не ріс 4 хвилини - інструмент завис, його зупинено.");
            // DumpIt's driver dates from 2011; a modern Windows may refuse to load it.
            // Say so, and name what the operator can still do - a bare error code here
            // reads as "the collector is broken" when in fact the triage is complete.
            Ui.Note("          Найімовірніше, драйвер не завантажився (він 2011 року).");
            Ui.Note("          Запустіть MRCv120.exe вручну або оберіть пункт [4] —");
            Ui.Note("          дампи процесів без драйвера. Файли пам'яті з диска");
            Ui.Note("          зібрано в будь-якому разі.");
            gap("дамп оперативної пам'яті", "інструмент завершився кодом " + rc + ", файла немає");
            Write(manifest, new string[][] {
                new string[] { "status", "failed", Path.GetFileName(exe), rc.ToString(), "" } });
            return null;
        }

        Ui.Line("      [OK] Дамп: " + Ui.Gb(size) + " ГБ за "
                + (t1 - t0).ToString(@"hh\:mm\:ss"), Ui.Sev.Good);
        Ui.Note("          Файл лишається на машині - у архів для бота він не входить.");
        Write(manifest, new string[][] {
            new string[] { "status", "ok", Path.GetFileName(exe), Path.GetFileName(outFile), "" },
            new string[] { "path", outFile, "", "", "" },
            new string[] { "size_bytes", size.ToString(), "", "", "" },
            new string[] { "ram_bytes", ramBytes.ToString(), "", "", "" },
            new string[] { "started", t0.ToString("yyyy-MM-dd HH:mm:ss"), "", "", "" },
            new string[] { "finished", t1.ToString("yyyy-MM-dd HH:mm:ss"), "", "", "" },
            // Deliberately NOT hashed here: SHA256 of a 128 GB dump costs another 10+ minutes
            // on the victim's machine. Hash it later, on the analyst's workstation.
            new string[] { "hash", "not_computed_on_target", "", "", "" },
        });
        return outFile;
    }

    /// <summary>
    /// Size of the dump the tool left behind: the file we asked for, or else the newest large
    /// file that appeared in the folder while we were running - never an older one that
    /// happened to sit there. `outFile` is updated to whatever was found.
    /// </summary>
    static long Newest(string dest, string wanted, DateTime since, ref string outFile)
    {
        long size = 0;
        try { if (File.Exists(wanted)) size = new FileInfo(wanted).Length; } catch { }
        if (size > 0) { outFile = wanted; return size; }
        try
        {
            DateTime best = since.AddSeconds(-5);
            long bestSize = 0;
            foreach (string f in Directory.GetFiles(dest))
            {
                FileInfo fi = new FileInfo(f);
                if (fi.LastWriteTime >= best && fi.Length > 268435456L && fi.Length > bestSize)
                { outFile = f; bestSize = fi.Length; }
            }
            return bestSize;
        }
        catch { return 0; }
    }

    // ---- driverless mode: targeted process dumps ---------------------------------

    [DllImport("dbghelp.dll", SetLastError = true)]
    static extern bool MiniDumpWriteDump(IntPtr hProcess, uint pid, IntPtr hFile, int type,
                                         IntPtr exceptionParam, IntPtr userStream, IntPtr callback);

    const int MiniDumpWithFullMemory = 0x00000002;

    /// <summary>
    /// No driver, no bugcheck risk: userland MiniDumpWriteDump over processes that look worth
    /// keeping - anything running from outside Windows\ and Program Files\. For a critical
    /// server this is the only memory acquisition that is safe to authorise.
    /// </summary>
    public static void CaptureProcesses(string outDir, Action<string, string> gap)
    {
        string dir = Path.Combine(outDir, @"memory\procdumps");
        Directory.CreateDirectory(dir);
        StringBuilder idx = new StringBuilder();
        idx.AppendLine("pid,name,path,dump_file,size_bytes,note");

        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows)
                     .TrimEnd('\\').ToLowerInvariant();
        string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
                    .TrimEnd('\\').ToLowerInvariant();
        string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
                      .TrimEnd('\\').ToLowerInvariant();

        int done = 0;
        long budget = 4L * 1073741824L;      // never fill the evidence disk

        foreach (Process p in Process.GetProcesses())
        {
            if (budget <= 0) break;
            string path = "", name = "";
            try { name = p.ProcessName; } catch { }
            try { path = p.MainModule.FileName; } catch { path = ""; }
            if (path.Length == 0) continue;              // protected/system process
            string low = path.ToLowerInvariant();
            if (low.StartsWith(win) || low.StartsWith(pf) || low.StartsWith(pf86)) continue;

            string dumpFile = Path.Combine(dir, name + "_" + p.Id + ".dmp");
            long sz = 0;
            string note = "";
            try
            {
                using (FileStream fs = new FileStream(dumpFile, FileMode.Create, FileAccess.Write))
                {
                    IntPtr h = fs.SafeFileHandle.DangerousGetHandle();
                    if (!MiniDumpWriteDump(p.Handle, (uint)p.Id, h, MiniDumpWithFullMemory,
                                           IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                        note = "MiniDumpWriteDump error " + Marshal.GetLastWin32Error();
                }
                sz = new FileInfo(dumpFile).Length;
                if (note.Length > 0 || sz == 0) { try { File.Delete(dumpFile); } catch { } sz = 0; }
                else { budget -= sz; done++; }
            }
            catch (Exception ex)
            {
                note = ex.Message;
                try { File.Delete(dumpFile); } catch { }
            }
            idx.AppendLine(p.Id + "," + Env.Csv(name) + "," + Env.Csv(path) + ","
                         + Env.Csv(sz > 0 ? Path.GetFileName(dumpFile) : "") + "," + sz + ","
                         + Env.Csv(note));
        }

        try
        {
            File.WriteAllText(Path.Combine(dir, "index.csv"), idx.ToString(), new UTF8Encoding(false));
        }
        catch { }
        Ui.Note("   дампів процесів: " + done);
        if (done == 0) gap("дампи процесів", "жоден процес не вдалося вивантажити");
    }

    static void Write(string path, string[][] rows)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("key,value,tool,extra1,extra2");
        foreach (string[] r in rows)
            sb.AppendLine(Env.Csv(r[0]) + "," + Env.Csv(r[1]) + "," + Env.Csv(r[2]) + ","
                        + Env.Csv(r[3]) + "," + Env.Csv(r[4]));
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
        }
        catch { }
    }
}
