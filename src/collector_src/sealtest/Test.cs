// Test harness - compiled ONLY here, never shipped in the collector.
//
// Робить рівно те, що робитиме збирач: випадковий пароль, один прохід власним
// шифрувальником ZIP-AES по теці, потім Seal.Attach кладе в архів README і загорнутий
// пароль. Друкує пароль, щоб бік бота можна було перевірити і правильним, і неправильним.
using System;
using System.IO;

static class Ui
{
    public const string VER = "v4.9 (2026-09-19)";
    public static string Gb(long b) { return (b / 1073741824.0).ToString("0.0"); }
    public static void Note(string s) { Console.WriteLine("   " + s); }
}

static class Lp
{
    public static string Human(Exception ex) { return ex.GetType().Name + ": " + ex.Message; }
}

static class Runner
{
    public static int Run(string exe, string args, string workDir, string logPath,
                          string phase, string label, int timeoutMs)
    {
        System.Diagnostics.ProcessStartInfo psi =
            new System.Diagnostics.ProcessStartInfo(exe, args);
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        if (workDir != null) psi.WorkingDirectory = workDir;
        using (System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi))
        {
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit();
            return p.ExitCode;
        }
    }
}

static class Test
{
    static int Main(string[] argv)
    {
        if (argv.Length < 2)
        {
            Console.WriteLine("usage: SealTest <7za.exe> <folder-to-pack> [out.zip]");
            return 2;
        }
        string sevenZa = argv[0];
        string tree = argv[1];
        string outZip = argv.Length > 2 ? argv[2]
                        : Path.Combine(Path.GetDirectoryName(tree.TrimEnd('\\')), "TEST_output.zip");
        if (File.Exists(outZip)) File.Delete(outZip);

        string pw = Seal.NewPassword();
        DateTime t0 = DateTime.Now;

        // ВЛАСНИЙ шифрувальник: пароль не потрапляє в жоден командний рядок
        long last = 0;
        string err = ZipAes.Create(outZip, tree, pw, delegate (long d, long t)
        {
            if (d - last > (100L << 20)) { last = d; Console.Write("."); }
        });
        if (err != null) { Console.WriteLine("ZIP FAILED: " + err); return 1; }

        string err2 = Seal.Attach(sevenZa, outZip, pw, null);
        double sec = (DateTime.Now - t0).TotalSeconds;
        if (err2 != null) { Console.WriteLine("ATTACH FAILED: " + err2); return 1; }

        Console.WriteLine();
        Console.WriteLine("archive : " + outZip);
        Console.WriteLine("size    : " + new FileInfo(outZip).Length + " bytes");
        Console.WriteLine("time    : " + sec.ToString("0.0") + " s");
        Console.WriteLine("password: " + pw);
        Console.WriteLine("key id  : " + SealKey.KeyId);
        return 0;
    }
}
