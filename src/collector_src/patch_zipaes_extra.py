# -*- coding: utf-8 -*-
"""Дати архіватору змогу покласти в архів ще й окремий файл поза текою.

Потрібно для архіву памʼяті: дамп лежить окремо від теки з файлами памʼяті, а наш
архіватор пише архів цілком (дописувати до наявного він не вміє й не має).
"""
import io

P = r'C:\DFIR\pybuild\v4\ZipAes.cs'
s = io.open(P, encoding='utf-8-sig').read()
assert 'string extraFile' not in s, 'already patched'

old = """    public static string Create(string zipPath, string rootDir, string password,
                                Progress progress)
    {
        try
        {
            if (!Directory.Exists(rootDir)) return "немає теки " + rootDir;
            string[] files = Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories);
            if (files.Length == 0) return "у теці немає файлів";"""
new = """    public static string Create(string zipPath, string rootDir, string password,
                                Progress progress)
    {
        return Create(zipPath, rootDir, password, null, progress);
    }

    /// <summary>
    /// Те саме, плюс один файл поза текою (дамп памʼяті лежить окремо від memDir, а архів
    /// пишеться цілком: дописувати до наявного цей архіватор не вміє й не повинен).
    /// </summary>
    public static string Create(string zipPath, string rootDir, string password,
                                string extraFile, Progress progress)
    {
        try
        {
            List<string> all = new List<string>();
            if (rootDir != null && Directory.Exists(rootDir))
                all.AddRange(Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories));
            if (extraFile != null && File.Exists(extraFile)) all.Add(extraFile);
            if (all.Count == 0) return "немає жодного файлу для архіву";
            string[] files = all.ToArray();"""
assert old in s, 'Create anchor not found'
s = s.replace(old, new, 1)

# Імʼя в архіві: для файлу поза текою беремо саме імʼя файлу.
BS = chr(92)
old2 = ("                foreach (string path in files)" + chr(10) +
        "                {" + chr(10) +
        "                    string rel = path.Substring(rootDir.Length).TrimStart('" + BS + BS + "', '/')" + chr(10) +
        "                                     .Replace('" + BS + BS + "', '/');")
new2 = ("                foreach (string path in files)" + chr(10) +
        "                {" + chr(10) +
        "                    // файл поза текою (дамп памʼяті) кладемо під власним іменем" + chr(10) +
        "                    string rel = (rootDir != null && path.StartsWith(rootDir," + chr(10) +
        "                                      StringComparison.OrdinalIgnoreCase))" + chr(10) +
        "                                 ? path.Substring(rootDir.Length)" + chr(10) +
        "                                       .TrimStart('" + BS + BS + "', '/').Replace('" + BS + BS + "', '/')" + chr(10) +
        "                                 : Path.GetFileName(path);")
assert old2 in s, 'rel anchor not found'
s = s.replace(old2, new2, 1)

io.open(P, 'w', encoding='utf-8-sig', newline='\r\n').write(s.replace('\r\n', '\n'))
print('ZipAes.cs: an extra standalone file can be added')
