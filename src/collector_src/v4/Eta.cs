// Expected durations, so the operator is told how long to wait instead of watching a spinner.
//
// The baseline is what each phase took on the build host (measured 2026-09-05, FAST, live,
// a 1 TB NVMe system disk with ~1.2 M files). A target machine is rarely that fast, so the
// baseline is only the opening estimate: once the first phases have completed, their real
// durations are compared with the baseline and every remaining estimate is scaled by the
// median ratio. Two slow phases early on make the whole forecast honest, not optimistic.
//
// Phase keys are the labels Steps/Runner pass; an unknown key simply gets no estimate.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

static class Eta
{
    // seconds on the build host; see Steps.cs for what each phase is
    static readonly Dictionary<string, double> Base = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase)
    {
        // measured by the v4.5 control pass on the build host (_collector_timing.csv, FAST):
        { "unpack",   3 },
        { "1/4",    132 },   // KAPE targets (FAST: KapeTriage + small extras), 11.9k files / 2 GB
        { "2/4",    161 },   // KAPE modules (FAST set, without EvtxECmd_RDP)
        { "ps",      30 },   // vao_collect_all.ps1: tree, suspicious, MOTW, live snapshot
        { "exec",     5 },   // vao_triage execscan
        { "raw",      5 },   // hives, browser databases, RDP cache
        { "net",      5 },   // network snapshot
        { "3/4",     32 },   // zip input (-mx=1)
        { "4/4",     33 },   // zip output (-mx=5, thousands of small CSVs)
        { "RAM",   1200 },   // full memory capture, ~50 MB/s on a typical box
        { "5/5",    300 },   // zip memory
        { "footprint", 5 },
    };

    // the order Steps runs them in - what "remaining" means
    static readonly string[] Order = { "unpack", "1/4", "2/4", "ps", "exec", "raw", "net",
                                       "RAM", "footprint", "3/4", "4/4", "5/5" };

    static readonly Dictionary<string, double> Actual = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
    static readonly List<string> Planned = new List<string>();
    static readonly Dictionary<string, double> Override = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
    static readonly List<string[]> Timing = new List<string[]>();
    static DateTime _t0 = DateTime.Now;

    /// <summary>Which phases this run will execute (FAST has no RAM/5/5, etc.).</summary>
    public static void Plan(IEnumerable<string> phases)
    {
        Planned.Clear();
        Planned.AddRange(phases);
        _t0 = DateTime.Now;
    }

    /// <summary>A better opening estimate than the table (e.g. RAM size / 50 MB/s).</summary>
    public static void Expect(string phase, double seconds) { Override[phase] = seconds; }

    static double Scale()
    {
        List<double> ratios = new List<double>();
        foreach (KeyValuePair<string, double> kv in Actual)
        {
            double b;
            if (Base.TryGetValue(kv.Key, out b) && b >= 5 && kv.Value >= 2)
                ratios.Add(kv.Value / b);
        }
        if (ratios.Count == 0) return 1.0;
        ratios.Sort();
        double med = ratios[ratios.Count / 2];
        return Math.Max(0.5, Math.Min(6.0, med));
    }

    public static TimeSpan Expected(string phase)
    {
        double s;
        if (Override.TryGetValue(phase, out s)) return TimeSpan.FromSeconds(s * Scale());
        if (Base.TryGetValue(phase, out s)) return TimeSpan.FromSeconds(s * Scale());
        return TimeSpan.Zero;
    }

    /// <summary>Estimate for every planned phase not finished yet.</summary>
    public static TimeSpan Remaining()
    {
        double total = 0;
        foreach (string p in Planned)
            if (!Actual.ContainsKey(p)) total += Expected(p).TotalSeconds;
        return TimeSpan.FromSeconds(total);
    }

    public static void Done(string phase, TimeSpan took, bool ok)
    {
        Actual[phase] = took.TotalSeconds;
        Timing.Add(new string[] { phase, ((int)took.TotalSeconds).ToString(), ok ? "ok" : "fail",
                                  DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") });
    }

    /// <summary>
    /// _collector_timing.csv: what each phase really took on THIS machine. Two uses: the
    /// bot's coverage block can say how long the collection ran, and the next release can
    /// re-calibrate the baseline from real targets instead of the build host.
    /// </summary>
    public static void WriteCsv(string path)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("phase,seconds,status,finished_at");
        foreach (string[] r in Timing)
            sb.AppendLine(string.Join(",", r));
        sb.AppendLine("total," + (int)(DateTime.Now - _t0).TotalSeconds + ",ok," + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        try { File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false)); } catch { }
    }

    public static TimeSpan SinceStart { get { return DateTime.Now - _t0; } }
}
