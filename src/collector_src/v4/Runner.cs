// Runs an external tool with an append-only progress log. Replaces Modules\!DFIRbot\run_progress.ps1.
//
// The verbose output of KAPE and 7za is hidden into a log, the same way v3 did it, because the
// operator watching hundreds of file-copy lines cannot tell progress from a hang. What they
// get instead (2026-09-05): a start line with the expected duration, a heartbeat every 30 s
// with elapsed/expected and the last line the tool wrote, and a done line. No line is ever
// rewritten - the \r spinner "floated" whenever the console was resized.
//
// Two watchdogs, both learned in the field:
//   * a hard timeout (per call) kills a tool that runs past any reasonable expectation;
//   * a STALL detector kills a tool whose observable output (a file it is writing, or its
//     console) has not moved for `stallMs`. The RAM capture hung in a loop on one machine
//     with no timeout at all - the operator waited on a process that would never finish.

using System;
using System.Diagnostics;
using System.IO;
using System.Text;

static class Runner
{
    /// <summary>Something the caller can measure to prove the tool is alive (bytes written).</summary>
    public delegate long Watch();

    public static int Run(string exe, string args, string workDir, string logPath,
                          string phase, string label, int timeoutMs, string stdinText,
                          Watch watch, int stallMs)
    {
        Stopwatch sw = Stopwatch.StartNew();
        string last = "";
        object gate = new object();
        int lastBeat = 0;       // first heartbeat after 30 s, not at 0 s
        TimeSpan expected = Eta.Expected(phase);
        long lastProgressValue = -1;
        DateTime lastProgressAt = DateTime.Now;

        StreamWriter log = null;
        if (logPath != null) { try { log = new StreamWriter(logPath, true, new UTF8Encoding(false)); } catch { } }

        Ui.ProgressStart(phase, label, expected);
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            if (workDir != null) psi.WorkingDirectory = workDir;
            psi.RedirectStandardInput = stdinText != null;

            using (Process p = new Process())
            {
                p.StartInfo = psi;
                DataReceivedEventHandler sink = delegate (object s, DataReceivedEventArgs e)
                {
                    if (e.Data == null) return;
                    lock (gate)
                    {
                        if (log != null) { try { log.WriteLine(e.Data); } catch { } }
                        string t = e.Data.Trim();
                        if (t.Length > 0) { last = t; lastProgressAt = DateTime.Now; }
                    }
                };
                p.OutputDataReceived += sink;
                p.ErrorDataReceived += sink;
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                if (stdinText != null)
                {
                    try { p.StandardInput.Write(stdinText); p.StandardInput.Flush(); } catch { }
                }

                while (!p.WaitForExit(250))
                {
                    string cur;
                    lock (gate) cur = last;
                    if (watch != null)
                    {
                        long v = -1;
                        try { v = watch(); } catch { }
                        if (v != lastProgressValue) { lastProgressValue = v; lastProgressAt = DateTime.Now; }
                        if (v >= 0) cur = "записано " + Ui.Gb(v) + " ГБ" + (cur.Length > 0 ? "   " + cur : "");
                    }
                    Ui.ProgressBeat(phase, sw.Elapsed, expected, cur, ref lastBeat);
                    if (timeoutMs > 0 && sw.ElapsedMilliseconds > timeoutMs)
                    {
                        try { p.Kill(); } catch { }
                        sw.Stop();
                        Ui.ProgressDone(phase, label + " (перевищено час " + Ui.Short(TimeSpan.FromMilliseconds(timeoutMs)) + ")", sw.Elapsed, false);
                        Eta.Done(phase, sw.Elapsed, false);
                        return -2;
                    }
                    if (stallMs > 0 && (DateTime.Now - lastProgressAt).TotalMilliseconds > stallMs)
                    {
                        try { p.Kill(); } catch { }
                        sw.Stop();
                        Ui.ProgressDone(phase, label + " (немає поступу " + Ui.Short(TimeSpan.FromMilliseconds(stallMs)) + " - зупинено)", sw.Elapsed, false);
                        Eta.Done(phase, sw.Elapsed, false);
                        return -3;
                    }
                }
                p.WaitForExit();
                sw.Stop();
                Ui.ProgressDone(phase, label, sw.Elapsed, p.ExitCode == 0);
                Eta.Done(phase, sw.Elapsed, p.ExitCode == 0);
                return p.ExitCode;
            }
        }
        catch (Exception ex)
        {
            sw.Stop();
            Ui.ProgressDone(phase, label + " - " + Lp.Human(ex), sw.Elapsed, false);
            Eta.Done(phase, sw.Elapsed, false);
            return -1;
        }
        finally
        {
            if (log != null) { try { log.Flush(); log.Close(); } catch { } }
        }
    }

    /// <summary>
    /// Same progress treatment, but the tool's stdout comes back to the caller (the KEY|value
    /// contract our PowerShell helpers and vao_triage speak). Until 2026-09-05 those steps ran
    /// through Env.TryRun, which blocks silently for up to an hour - the FAST profile looked
    /// hung during the whole PowerShell pass because nothing was printed at all.
    /// </summary>
    public static string[] RunCapture(string exe, string args, string workDir, string logPath,
                                      string phase, string label, int timeoutMs, string stdinText,
                                      int stallMs, out bool ok)
    {
        Stopwatch sw = Stopwatch.StartNew();
        string last = "";
        object gate = new object();
        int lastBeat = 0;       // first heartbeat after 30 s, not at 0 s
        TimeSpan expected = Eta.Expected(phase);
        DateTime lastProgressAt = DateTime.Now;
        StringBuilder outp = new StringBuilder();
        ok = false;

        StreamWriter log = null;
        if (logPath != null) { try { log = new StreamWriter(logPath, true, new UTF8Encoding(false)); } catch { } }

        Ui.ProgressStart(phase, label, expected);
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            if (workDir != null) psi.WorkingDirectory = workDir;
            psi.RedirectStandardInput = stdinText != null;

            using (Process p = new Process())
            {
                p.StartInfo = psi;
                DataReceivedEventHandler sink = delegate (object s, DataReceivedEventArgs e)
                {
                    if (e.Data == null) return;
                    lock (gate)
                    {
                        outp.AppendLine(e.Data);
                        if (log != null) { try { log.WriteLine(e.Data); } catch { } }
                        string t = e.Data.Trim();
                        // VAO_STEP lines are the helper's own phase markers - the most useful
                        // thing to show; other output is the last line, whatever it is
                        if (t.Length > 0) { last = t; lastProgressAt = DateTime.Now; }
                    }
                };
                p.OutputDataReceived += sink;
                p.ErrorDataReceived += sink;
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                if (stdinText != null)
                {
                    try { p.StandardInput.Write(stdinText); p.StandardInput.Close(); } catch { }
                }
                while (!p.WaitForExit(250))
                {
                    string cur;
                    lock (gate) cur = last;
                    Ui.ProgressBeat(phase, sw.Elapsed, expected, cur, ref lastBeat);
                    if (timeoutMs > 0 && sw.ElapsedMilliseconds > timeoutMs)
                    {
                        try { p.Kill(); } catch { }
                        sw.Stop();
                        Ui.ProgressDone(phase, label + " (перевищено час)", sw.Elapsed, false);
                        Eta.Done(phase, sw.Elapsed, false);
                        lock (gate) return outp.ToString().Replace("\r\n", "\n").Split('\n');
                    }
                    if (stallMs > 0 && (DateTime.Now - lastProgressAt).TotalMilliseconds > stallMs)
                    {
                        try { p.Kill(); } catch { }
                        sw.Stop();
                        Ui.ProgressDone(phase, label + " (немає поступу - зупинено)", sw.Elapsed, false);
                        Eta.Done(phase, sw.Elapsed, false);
                        lock (gate) return outp.ToString().Replace("\r\n", "\n").Split('\n');
                    }
                }
                p.WaitForExit();
                sw.Stop();
                ok = p.ExitCode == 0;
                Ui.ProgressDone(phase, label, sw.Elapsed, ok);
                Eta.Done(phase, sw.Elapsed, ok);
                lock (gate) return outp.ToString().Replace("\r\n", "\n").Split('\n');
            }
        }
        catch (Exception ex)
        {
            sw.Stop();
            Ui.ProgressDone(phase, label + " - " + Lp.Human(ex), sw.Elapsed, false);
            Eta.Done(phase, sw.Elapsed, false);
            return null;
        }
        finally
        {
            if (log != null) { try { log.Flush(); log.Close(); } catch { } }
        }
    }

    /// <summary>stdin, no watch - what DumpIt's confirmation prompt needs.</summary>
    public static int Run(string exe, string args, string workDir, string logPath,
                          string phase, string label, int timeoutMs, string stdinText)
    {
        return Run(exe, args, workDir, logPath, phase, label, timeoutMs, stdinText, null, 0);
    }

    /// <summary>Overload without stdin - what every existing caller uses.</summary>
    public static int Run(string exe, string args, string workDir, string logPath,
                          string phase, string label, int timeoutMs)
    {
        return Run(exe, args, workDir, logPath, phase, label, timeoutMs, null, null, 0);
    }

    /// <summary>Run a tool quietly and return its stdout (used for our own vao_* tools).</summary>
    public static string[] Capture(string exe, string args, string workDir, int timeoutMs)
    {
        string outp;
        ProcessStartInfo psi = new ProcessStartInfo(exe, args);
        if (workDir != null) psi.WorkingDirectory = workDir;
        bool ok = Env.TryRun(exe, args, null, out outp, timeoutMs);
        if (!ok && outp == null) return null;
        return (outp ?? "").Replace("\r\n", "\n").Split('\n');
    }
}
