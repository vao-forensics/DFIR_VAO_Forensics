// Long paths. A field run (2026-09-05) ended in red with the .NET PathTooLongException
// text - "Полное имя файла должно содержать меньше 260 знаков, а имя каталога - меньше 248" -
// because a profile on that machine had a tree deeper than MAX_PATH and one of our own file
// operations was not wrapped. The collector must never die on a path; it must copy what it
// can and record what it could not.
//
// Three layers, all needed:
//   1. Program.Main flips the runtime switches so System.IO on .NET 4.6.2+ accepts paths
//      longer than MAX_PATH and the \\?\ prefix (legacy handling refuses both);
//   2. the manifest declares longPathAware (helps only where the OS policy is on);
//   3. this class prefixes \\?\ to any path that is at or near the limit, so the Win32
//      layer stops normalising and rejecting it regardless of policy.
// Every enumerate/copy/move/delete in Steps goes through here. A path we still cannot
// handle is counted, and the count becomes one honest row in collection_gaps.csv.

using System;
using System.Collections.Generic;
using System.IO;

static class Lp
{
    const string PREFIX = @"\\?\";
    const string UNC_PREFIX = @"\\?\UNC\";
    const int NEAR = 240;   // prefix earlier than 260: Path.Combine on the way down adds length

    public static int Skipped;              // paths we had to give up on
    public static List<string> Samples = new List<string>();

    public static void Reset() { Skipped = 0; Samples.Clear(); }

    /// <summary>Path with the \\?\ prefix when it is long enough to need one.</summary>
    public static string P(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;
        if (path.StartsWith(PREFIX, StringComparison.Ordinal)) return path;
        if (path.Length < NEAR) return path;
        if (path.StartsWith(@"\\", StringComparison.Ordinal))
            return UNC_PREFIX + path.Substring(2);
        return PREFIX + path;
    }

    /// <summary>Back to a plain path for display and for tools that do not accept the prefix.</summary>
    public static string Plain(string path)
    {
        if (path == null) return null;
        if (path.StartsWith(UNC_PREFIX, StringComparison.Ordinal)) return @"\\" + path.Substring(UNC_PREFIX.Length);
        if (path.StartsWith(PREFIX, StringComparison.Ordinal)) return path.Substring(PREFIX.Length);
        return path;
    }

    static void Note(string path)
    {
        Skipped++;
        if (Samples.Count < 5) Samples.Add(Plain(path));
    }

    public static bool IsTooLong(Exception ex)
    {
        return ex is PathTooLongException
            || (ex != null && ex.Message != null && ex.Message.IndexOf("260", StringComparison.Ordinal) >= 0
                && ex.Message.IndexOf("248", StringComparison.Ordinal) >= 0);
    }


    /// Our own wording for the exceptions that reach the operator's screen.
    /// .NET localises its messages to the OS language, so on a Russian-locale Windows the
    /// runtime text arrives in Russian - which is not something to show a Ukrainian
    /// investigator in the middle of a collection.
    public static string Human(Exception ex)
    {
        if (ex == null) return "невідома помилка";
        if (IsTooLong(ex))
            return "шлях довший за дозволений Windows (260 символів) - цей елемент пропущено, "
                 + "решта збирається далі";
        if (ex is UnauthorizedAccessException)
            return "немає доступу до файлу або теки - потрібні права адміністратора";
        if (ex is DirectoryNotFoundException)
            return "теку не знайдено - її могли видалити під час збору";
        if (ex is FileNotFoundException)
            return "файл не знайдено - його могли видалити під час збору";
        if (ex is IOException && ex.Message != null
            && ex.Message.IndexOf("space", StringComparison.OrdinalIgnoreCase) >= 0)
            return "бракує місця на диску призначення";
        if (ex is IOException)
            return "файл зайнятий іншою програмою або недоступний";
        if (ex is OperationCanceledException)
            return "операцію скасовано";
        return ex.GetType().Name + ": " + ex.Message;
    }

    public static string[] Dirs(string dir)
    {
        try { return Directory.GetDirectories(P(dir)); }
        catch (Exception ex) { if (IsTooLong(ex)) Note(dir); return null; }
    }

    public static string[] Files(string dir)
    {
        try { return Directory.GetFiles(P(dir)); }
        catch (Exception ex) { if (IsTooLong(ex)) Note(dir); return null; }
    }

    /// <summary>Enumerate every file under a root without dying on one directory.</summary>
    public static IEnumerable<string> Walk(string root)
    {
        Stack<string> stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            string d = stack.Pop();
            string[] subs = Dirs(d), files = Files(d);
            if (subs != null) foreach (string s in subs) stack.Push(s);
            if (files != null) foreach (string f in files) yield return f;
        }
    }

    public static bool Copy(string src, string dst)
    {
        try
        {
            string d = Path.GetDirectoryName(Plain(dst));
            if (d != null) Directory.CreateDirectory(P(d));
            File.Copy(P(src), P(dst), true);
            return true;
        }
        catch (Exception ex) { if (IsTooLong(ex)) Note(src); return false; }
    }

    public static bool Move(string src, string dst)
    {
        try
        {
            string d = Path.GetDirectoryName(Plain(dst));
            if (d != null) Directory.CreateDirectory(P(d));
            File.Move(P(src), P(dst));
            return true;
        }
        catch (Exception ex) { if (IsTooLong(ex)) Note(src); return false; }
    }

    public static long Size(string path)
    {
        try { return new FileInfo(P(path)).Length; }
        catch (Exception ex) { if (IsTooLong(ex)) Note(path); return -1; }
    }

    public static bool Delete(string path)
    {
        try { File.Delete(P(path)); return true; }
        catch (Exception ex) { if (IsTooLong(ex)) Note(path); return false; }
    }

    public static bool Exists(string path)
    {
        try { return File.Exists(P(path)); } catch { return false; }
    }

    public static bool DirExists(string path)
    {
        try { return Directory.Exists(P(path)); } catch { return false; }
    }

    /// <summary>One-line summary for the gap file; empty when nothing was skipped.</summary>
    public static string GapText()
    {
        if (Skipped == 0) return "";
        return Skipped + " шлях(ів) довші за MAX_PATH пропущено, напр. "
             + string.Join(" ; ", Samples.ToArray());
    }
}
