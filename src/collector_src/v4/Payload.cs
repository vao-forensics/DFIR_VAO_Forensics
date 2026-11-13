// The toolkit travels appended to this executable as an UNCOMPRESSED zip overlay:
//
//     [ PE ][ stored zip ][ int64 zip offset ][ "DFIRPAY1" ]
//
// Two things this buys, both measured (2026-08-09):
//   * nothing is written to the target disk before the operator has answered the menu, and
//     only the tier the answer needs is written at all - FAST puts 339 MB on disk in 2.1 s,
//     where the old PyInstaller build wrote ~1.76 GB on every single run;
//   * the launcher can be tiny, so Defender's first-run scan of an unsigned binary is short.
//
// Do NOT read the overlay into memory: pass the file stream to ZipArchive, which handles the
// prepended PE exactly the way a self-extracting zip does.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;

/// <summary>A read-only window onto part of another stream.</summary>
class SubStream : Stream
{
    readonly Stream _base; readonly long _off, _len; long _pos;
    public SubStream(Stream b, long off, long len) { _base = b; _off = off; _len = len; }
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
        Position = t; return _pos;
    }
    public override void SetLength(long v) { throw new NotSupportedException(); }
    public override void Write(byte[] b, int o, int c) { throw new NotSupportedException(); }
}

static class Payload
{
    const string MAGIC = "DFIRPAY1";

    public static string SelfPath
    {
        get { return Process.GetCurrentProcess().MainModule.FileName; }
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

    public static bool Present { get { long o; return ReadFooter(SelfPath, out o); } }

    /// <summary>
    /// Extract the members belonging to the requested tiers into <paramref name="work"/>.
    /// Returns false and leaves an explanation in <paramref name="error"/> on failure.
    /// </summary>
    public static bool Extract(string work, bool full, out string error, out int files, out long bytes)
    {
        error = null; files = 0; bytes = 0;
        string me = SelfPath;
        long off;
        if (!ReadFooter(me, out off))
        {
            error = "службові дані не знайдено - завантажте збирач ще раз";
            return false;
        }
        Stopwatch sw = Stopwatch.StartNew();
        try
        {
            using (FileStream fs = new FileStream(me, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (SubStream sub = new SubStream(fs, off, fs.Length - 16 - off))
            using (ZipArchive zip = new ZipArchive(sub, ZipArchiveMode.Read))
            {
                ZipArchiveEntry man = zip.GetEntry("_tiers.txt");
                if (man == null) { error = "немає опису складу"; return false; }

                List<string> want = new List<string>();
                using (StreamReader rd = new StreamReader(man.Open(), Encoding.UTF8))
                {
                    string line;
                    while ((line = rd.ReadLine()) != null)
                    {
                        int t = line.IndexOf('\t');
                        if (t <= 0) continue;
                        string tier = line.Substring(0, t);
                        if (tier == "core" || tier == "fast" || (tier == "full" && full))
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
                    files++;
                    if (files % 250 == 0 || files == total)
                    {
                        int pct = total > 0 ? (int)(files * 100L / total) : 100;
                        Console.Write("\r     розпакування   [" + new string('#', pct / 4)
                            + new string('.', 25 - pct / 4) + "] " + pct.ToString().PadLeft(3)
                            + "%  " + files + "/" + total + "   ");
                    }
                }
            }
        }
        catch (Exception ex) { error = ex.Message; return false; }
        sw.Stop();
        Console.WriteLine();
        Console.WriteLine("     готово: " + files + " файлів, " + (bytes / 1048576) + " МБ, за "
                          + sw.Elapsed.TotalSeconds.ToString("0.0") + " с");
        return true;
    }

    /// <summary>Best-effort recursive delete; KAPE leaves long paths and locked handles.</summary>
    public static void KillDir(string dir)
    {
        for (int i = 0; i < 6; i++)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); return; }
            catch { System.Threading.Thread.Sleep(700); }
        }
    }
}
