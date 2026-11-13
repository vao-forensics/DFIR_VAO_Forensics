// Thin P/Invoke layer. Kept in one file so every unmanaged call the collector makes is
// visible in one place - on an evidence machine we must be able to say exactly what we touched.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

static class Native
{
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int h);
    [DllImport("kernel32.dll")] static extern bool GetConsoleMode(IntPtr h, out uint m);
    [DllImport("kernel32.dll")] static extern bool SetConsoleMode(IntPtr h, uint m);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec,
                                     uint disp, uint flags, IntPtr templ);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(IntPtr h, byte[] buf, uint n, out uint read, IntPtr ov);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern bool SetFileAttributesW(string path, uint attrs);

    const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_RW = 0x00000003;
    const uint OPEN_EXISTING = 3;

    public static void DisableQuickEdit()
    {
        IntPtr hIn = GetStdHandle(-10);
        uint mode;
        if (GetConsoleMode(hIn, out mode))
            SetConsoleMode(hIn, (mode & ~0x0040u) | 0x0080u);   // -QUICK_EDIT +EXTENDED_FLAGS
    }

    public static void Hide(string path)
    {
        try { SetFileAttributesW(path, 0x2); } catch { }
    }

    /// <summary>
    /// Read the first sectors of a physical disk. This is the only way to see a boot-sector
    /// signature (BitLocker -FVE-FS-, VeraCrypt loader, LUKS...) - WMI cannot.
    /// Returns null when the read is not possible; callers MUST treat null as "not checked",
    /// never as "clean". That confusion is exactly what told the operator "шифрування не
    /// виявлено" on a fully encrypted machine.
    /// </summary>
    public static byte[] ReadPhysicalSectors(int driveIndex, int bytes)
    {
        IntPtr h = CreateFileW(@"\\.\PHYSICALDRIVE" + driveIndex, GENERIC_READ, FILE_SHARE_RW,
                               IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == IntPtr.Zero || h.ToInt64() == -1) return null;
        try
        {
            // Reads on a raw volume handle must be a multiple of the sector size.
            int n = ((bytes + 511) / 512) * 512;
            byte[] buf = new byte[n];
            uint read;
            if (!ReadFile(h, buf, (uint)n, out read, IntPtr.Zero)) return null;
            if (read < 512) return null;
            byte[] outp = new byte[read];
            Buffer.BlockCopy(buf, 0, outp, 0, (int)read);
            return outp;
        }
        catch { return null; }
        finally { CloseHandle(h); }
    }

    // ---- alternate data streams (Ads.cs) ------------------------------------------------
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string cStreamName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr FindFirstStreamW(string name, int level, out WIN32_FIND_STREAM_DATA data, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool FindNextStreamW(IntPtr h, out WIN32_FIND_STREAM_DATA data);

    [DllImport("kernel32.dll")]
    static extern bool FindClose(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileSizeEx(IntPtr h, out long size);

    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;   // needed to open a folder's stream

    /// <summary>Named streams of a file or folder: (name without ':' and ':$DATA', size).
    /// The unnamed main stream "::$DATA" is left out.</summary>
    public static List<KeyValuePair<string, long>> ListStreams(string path)
    {
        List<KeyValuePair<string, long>> res = new List<KeyValuePair<string, long>>();
        WIN32_FIND_STREAM_DATA d;
        IntPtr h = FindFirstStreamW(path, 0, out d, 0);
        if (h == IntPtr.Zero || h.ToInt64() == -1) return res;
        try
        {
            do
            {
                string n = d.cStreamName ?? "";
                if (n.EndsWith(":$DATA", StringComparison.Ordinal)) n = n.Substring(0, n.Length - 6);
                else continue;                                   // other stream types carry no data
                if (n.StartsWith(":")) n = n.Substring(1);
                if (n.Length > 0) res.Add(new KeyValuePair<string, long>(n, d.StreamSize));
            } while (FindNextStreamW(h, out d));
        }
        finally { FindClose(h); }
        return res;
    }

    /// <summary>Read up to max bytes of "path:stream". Null when it cannot be opened.</summary>
    public static byte[] ReadStream(string pathAndStream, long max)
    {
        IntPtr h = CreateFileW(pathAndStream, GENERIC_READ, FILE_SHARE_RW | 0x4, IntPtr.Zero,
                               OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (h == IntPtr.Zero || h.ToInt64() == -1) return null;
        try
        {
            long size;
            if (!GetFileSizeEx(h, out size) || size > max) return null;
            byte[] buf = new byte[size];
            int off = 0;
            while (off < size)
            {
                byte[] chunk = new byte[Math.Min(65536, size - off)];
                uint read;
                if (!ReadFile(h, chunk, (uint)chunk.Length, out read, IntPtr.Zero) || read == 0) break;
                Buffer.BlockCopy(chunk, 0, buf, off, (int)read);
                off += (int)read;
            }
            if (off == size) return buf;
            byte[] part = new byte[off];
            Buffer.BlockCopy(buf, 0, part, 0, off);
            return part;
        }
        catch { return null; }
        finally { CloseHandle(h); }
    }

    /// <summary>Case-insensitive search for an ASCII marker inside a byte buffer.</summary>
    public static bool Contains(byte[] hay, string needle)
    {
        if (hay == null || needle == null) return false;
        byte[] n = System.Text.Encoding.ASCII.GetBytes(needle);
        if (n.Length == 0 || hay.Length < n.Length) return false;
        for (int i = 0; i <= hay.Length - n.Length; i++)
        {
            int j = 0;
            while (j < n.Length && hay[i + j] == n[j]) j++;
            if (j == n.Length) return true;
        }
        return false;
    }
}
