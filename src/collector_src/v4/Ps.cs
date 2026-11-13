// PowerShell bridge - the fallback that keeps v4 working while the helper scripts are being
// ported to C#, and the reason the 2026-08-13 host is no longer a dead end.
//
// THE MECHANISM (verified on a host with the policy forced to Restricted):
//   powershell -File script.ps1     -> "cannot be loaded because running scripts is disabled"
//   script text piped to -Command - -> runs
// ExecutionPolicy governs script FILES, not command text. Group Policy can also force the
// policy in a way that OVERRIDES our -ExecutionPolicy Bypass parameter, so passing the flag
// is not a fix; not using a file is.
//
// stdin is used rather than -EncodedCommand because a command line is capped near 32 KB and
// find_suspicious.ps1 alone is 17.7 KB of source, which base64 of UTF-16 would blow past.
// The script body is base64'd INSIDE the stdin text purely to sidestep quoting: the payload
// then contains no quotes, backticks or here-string terminators that could end it early.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

static class Ps
{
    public static bool Available;      // set once from Env
    public static bool UseStdin;       // true when .ps1 files are blocked but stdin works
    static string _exe;

    public static void Init(Env env)
    {
        _exe = Env.PsExe();
        Available = _exe != null && (env.PsFileState == "OK" || env.PsStdinState == "OK");
        // ALWAYS prefer stdin, even where .ps1 files are allowed. Two reasons, one of them
        // learned the hard way on 2026-08-13:
        //   * with -File, powershell does NOT strip single quotes from argument values, so
        //     -OutDir 'C:\x' arrived as a literal "'C:\x'". Four analysis steps wrote nowhere
        //     and reported zero, and the run still looked successful.
        //     Through the bridge the arguments are parsed by PowerShell itself, so normal
        //     quoting rules apply.
        //   * one code path means the behaviour tested here is the behaviour a locked-down
        //     target machine gets.
        UseStdin = env.PsStdinState == "OK";
    }

    /// <summary>
    /// Run a .ps1 from the extracted toolkit with named parameters, capturing stdout.
    /// Returns null when PowerShell cannot be used at all - callers MUST record that as a
    /// gap rather than pretending the step produced nothing to find.
    /// </summary>
    public static string[] Run(string scriptPath, Dictionary<string, string> args, int timeoutMs)
    {
        return Run(scriptPath, args, timeoutMs, null, null, null);
    }

    /// <summary>
    /// With a phase/label the run goes through Runner.RunCapture and the operator sees a
    /// start line, heartbeats and a done line; without them it is the old silent call.
    /// </summary>
    public static string[] Run(string scriptPath, Dictionary<string, string> args, int timeoutMs,
                               string phase, string label, string logPath)
    {
        if (!Available || !File.Exists(scriptPath)) return null;

        string outp = null;
        bool ok;
        if (!UseStdin)
        {
            // Fallback only. Double quotes, because -File passes values through literally.
            string a = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + scriptPath + "\" " + FileFlags(args);
            if (phase != null)
                return Runner.RunCapture(_exe, a, null, logPath, phase, label, timeoutMs, null, 0, out ok);
            ok = Env.TryRun(_exe, a, null, out outp, timeoutMs);
        }
        else
        {
            string body = File.ReadAllText(scriptPath);
            string b64 = Convert.ToBase64String(new UTF8Encoding(false).GetBytes(body));
            StringBuilder sb = new StringBuilder();
            // [scriptblock]::Create keeps the script's own param() block working, so the
            // helpers need no modification to run through this path.
            sb.AppendLine("$ErrorActionPreference='Continue'");
            sb.AppendLine("$__b='" + b64 + "'");
            sb.AppendLine("$__s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($__b))");
            sb.AppendLine("$__sb=[scriptblock]::Create($__s)");
            // DOT-SOURCE, not call. Measured difference, not a style choice: with "&" the
            // block runs in a child scope, so a helper that writes $script:counts inside a
            // function updates a DIFFERENT hashtable than the one it prints at the end.
            // collect_liveresponse.ps1 wrote all five CSVs correctly and still reported
            // PROC|0 CONN|0 PIPE|0. Dot-sourcing reproduces script-file semantics: 241/360/105.
            sb.AppendLine(". $__sb " + Flags(args));
            if (phase != null)
                return Runner.RunCapture(_exe, "-NoProfile -NonInteractive -Command -", null, logPath,
                                         phase, label, timeoutMs, sb.ToString(), 0, out ok);
            ok = Env.TryRun(_exe, "-NoProfile -NonInteractive -Command -", sb.ToString(), out outp, timeoutMs);
        }
        if (outp == null) return ok ? new string[0] : null;
        return outp.Replace("\r\n", "\n").Split('\n');
    }

    /// <summary>Quoting for the -File fallback, where values pass through literally.</summary>
    static string FileFlags(Dictionary<string, string> args)
    {
        if (args == null) return "";
        StringBuilder sb = new StringBuilder();
        foreach (KeyValuePair<string, string> kv in args)
            sb.Append(" -").Append(kv.Key).Append(" \"")
              .Append((kv.Value ?? "").Replace("\"", "\\\"")).Append("\"");
        return sb.ToString();
    }

    /// <summary>Quoting for the bridge, where PowerShell itself parses the arguments.</summary>
    static string Flags(Dictionary<string, string> args)
    {
        if (args == null) return "";
        StringBuilder sb = new StringBuilder();
        foreach (KeyValuePair<string, string> kv in args)
        {
            sb.Append(" -").Append(kv.Key).Append(" '");
            sb.Append((kv.Value ?? "").Replace("'", "''"));   // PowerShell single-quote escape
            sb.Append("'");
        }
        return sb.ToString();
    }

    /// <summary>Parse the "KEY|value" contract every helper script emits.</summary>
    public static Dictionary<string, string> Kv(string[] lines)
    {
        Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (lines == null) return d;
        foreach (string raw in lines)
        {
            if (raw == null) continue;
            string s = raw.Trim();
            int i = s.IndexOf('|');
            if (i <= 0) continue;
            string k = s.Substring(0, i).Trim();
            // Guard against the v3 disaster in miniature: only accept keys that look like
            // keys, so an error line can never be mistaken for a value.
            bool clean = k.Length > 0 && k.Length <= 16;
            foreach (char c in k)
                if (!char.IsLetterOrDigit(c) && c != '_') { clean = false; break; }
            if (clean) d[k] = s.Substring(i + 1).Trim();
        }
        return d;
    }
}
