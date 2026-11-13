// Drive-letter handling. Port of Modules\!DFIRbot\resolve_drive.ps1.
//
// Why a whole file for one letter: the operator types on a Ukrainian keyboard, so "С" is very
// often the CYRILLIC es (U+0421), not Latin C. v3 resolved that in PowerShell - and when
// PowerShell was blocked, the resolver's ERROR TEXT became the drive letter and the collector
// looped forever asking again. Doing it in-process removes both problems.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

static class Drives
{
    // Cyrillic letters that look identical to Latin ones, upper and lower case.
    const string CYR = "АВЕКМНОРСТУХІЅЈавекмнорстухіѕј";
    const string LAT = "ABEKMHOPCTYXISJabekmhopctyxisj";

    public static string Normalize(string s)
    {
        if (s == null) return null;
        StringBuilder sb = new StringBuilder();
        foreach (char ch in s.Trim())
        {
            if (ch == ':' || ch == '\\' || ch == '/' || ch == '"' || ch == '\'') continue;
            int i = CYR.IndexOf(ch);
            sb.Append(i >= 0 ? LAT[i] : ch);
        }
        string r = sb.ToString().Trim().ToUpperInvariant();
        if (r.Length == 0) return null;
        char c = r[0];
        return (c >= 'A' && c <= 'Z') ? c.ToString() : null;
    }

    public static bool Exists(string letter)
    {
        if (letter == null) return false;
        try { return Directory.Exists(letter + @":\"); } catch { return false; }
    }

    public static string ListLetters()
    {
        List<string> l = new List<string>();
        try
        {
            foreach (DriveInfo d in DriveInfo.GetDrives())
                if (d.IsReady) l.Add(d.Name.TrimEnd('\\'));
        }
        catch { }
        return l.Count == 0 ? "(не вдалося перелічити)" : string.Join(" ", l.ToArray());
    }

    /// <summary>Fixed and removable ready drives, biggest free space first.</summary>
    public static List<DriveInfo> Writable()
    {
        List<DriveInfo> l = new List<DriveInfo>();
        try
        {
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                if (!d.IsReady) continue;
                if (d.DriveType != DriveType.Fixed && d.DriveType != DriveType.Removable
                    && d.DriveType != DriveType.Network) continue;
                l.Add(d);
            }
        }
        catch { }
        l.Sort(delegate (DriveInfo a, DriveInfo b)
        { return b.AvailableFreeSpace.CompareTo(a.AvailableFreeSpace); });
        return l;
    }

    public static long FreeOn(string path)
    {
        try
        {
            string root = Path.GetPathRoot(Path.GetFullPath(path));
            return new DriveInfo(root).AvailableFreeSpace;
        }
        catch { return -1; }
    }
}
