# -*- coding: utf-8 -*-
"""Wire Seal.cs into the collector's packing step.

Kept as a script rather than done by hand so the change is reviewable and repeatable, the
way the other v4 patches in this folder are. Run it against a pristine Steps.cs; it restores
the newest .bak_seal_* backup first if one exists, so it can be re-run while iterating.

All three archives are sealed, not just the bot-facing one. Measured 2026-09-17 before
deciding: a 4.5 GB archive seals in 18 s at 255 MB/s and the bot reads it back in 14 s with
a byte-identical SHA-256, so neither the Zip64 boundary nor the time cost is a reason to
leave the raw and memory archives in the clear - and those two hold the most sensitive
material of the three. What sealing DOES need is a second copy of the file on the same disk
while both exist; Seal.Run checks for it and refuses with a reason, in which case that
archive stays plain and the operator is told so by name.
"""
import glob
import io
import os
import shutil
import sys
import time

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

P = r'C:\DFIR\pybuild\v4\Steps.cs'
baks = sorted(glob.glob(P + '.bak_seal_*'))
if baks:
    shutil.copy2(baks[-1], P)
    print('restored %s' % os.path.basename(baks[-1]))
else:
    shutil.copy2(P, P + '.bak_seal_' + time.strftime('%Y%m%d_%H%M%S'))

s = io.open(P, encoding='utf-8-sig').read()
assert 'Seal.Run' not in s, 'Steps.cs still wired - restore a clean copy first'

OLD = '''            Guard("архів пам'яті", delegate () { zipMem = PackMemory(sevenZa, c, work, memDir, ramDump, log); });
        }
        else Gap("пакування", "7za.exe не розпакувався");
'''
NEW = '''            Guard("архів пам'яті", delegate () { zipMem = PackMemory(sevenZa, c, work, memDir, ramDump, log); });

            // ---- encryption -----------------------------------------------------------
            // Every archive is sealed, each independently: if one cannot be sealed (no room
            // for a second copy of it while both exist) the others still are, and the
            // operator is told by name which one stayed in the clear. An archive that could
            // not be encrypted is still evidence - it is never deleted to protect it.
            zipOut = SealArchive(zipOut, "архів для бота", ref _sealOut);
            if (File.Exists(zipIn)) zipIn = SealArchive(zipIn, "архів сирих даних", ref _sealIn);
            if (zipMem != null && File.Exists(zipMem))
                zipMem = SealArchive(zipMem, "архів пам'яті", ref _sealMem);
        }
        else Gap("пакування", "7za.exe не розпакувався");
'''
assert OLD in s, 'packing block not found'
s = s.replace(OLD, NEW, 1)

# The operator has to be told what is protected and what is not, beside the file names.
OLD2 = '''            if (File.Exists(zipIn)) Console.WriteLine("     [сирі дані]   " + zipIn + Sz(zipIn));
        }'''
NEW2 = '''            if (File.Exists(zipIn)) Console.WriteLine("     [сирі дані]   " + zipIn + Sz(zipIn));
            SealReport(zipIn, zipMem);
        }'''
assert OLD2 in s, 'finish block not found'
s = s.replace(OLD2, NEW2, 1)

# The helpers, next to the other packing helpers.
OLD3 = '''    /// <summary>The bot's uploader ceiling. Anything above this cannot be sent the usual way.</summary>
    const long UPLOAD_LIMIT = 32L * 1073741824L;'''
NEW3 = '''    /// <summary>The bot's uploader ceiling. Anything above this cannot be sent the usual way.</summary>
    const long UPLOAD_LIMIT = 32L * 1073741824L;

    /// <summary>Which archives came out encrypted - for an honest closing report.</summary>
    static bool _sealOut, _sealIn, _sealMem;

    /// <summary>
    /// Encrypt one finished archive and return the path the operator should keep. On ANY
    /// failure the plain archive is returned unchanged and the reason is recorded as a gap:
    /// a collection that could not be encrypted is still a collection, and losing evidence
    /// in order to protect it would be the worse mistake. The plain file is deleted only
    /// after the container has been written AND reopened.
    /// </summary>
    static string SealArchive(string path, string label, ref bool flag)
    {
        if (!File.Exists(path)) return path;
        string err;
        long before = 0;
        try { before = new FileInfo(path).Length; } catch { }
        // the real elapsed time, not a zero: 4.5 GB measured at 18 s, and an operator
        // reading "0 с" beside a two-minute wait stops trusting the screen
        DateTime t0 = DateTime.Now;
        Ui.ProgressStart("seal", "Шифрування: " + label, TimeSpan.Zero);
        string box = Seal.Run(path, null, out err);
        if (box == null)
        {
            Ui.ProgressDone("seal", label + " - не зашифровано (" + (err ?? "невідомо") + ")",
                            DateTime.Now - t0, false);
            Gap("шифрування: " + label, err ?? "невідомо");
            return path;
        }
        try { File.Delete(path); } catch { }
        flag = true;
        Ui.ProgressDone("seal", label + " зашифровано (" + Ui.Gb(before) + " ГБ)",
                        DateTime.Now - t0, true);
        return box;
    }

    /// <summary>
    /// Say plainly which archives are protected and which are not. A half-encrypted output
    /// that the operator believes is fully encrypted is worse than no encryption at all -
    /// they would treat an open archive as a safe one.
    /// </summary>
    static void SealReport(string zipIn, string zipMem)
    {
        System.Collections.Generic.List<string> open = new System.Collections.Generic.List<string>();
        if (!_sealOut) open.Add("для бота");
        if (File.Exists(zipIn) && !_sealIn) open.Add("сирі дані");
        if (zipMem != null && File.Exists(zipMem) && !_sealMem) open.Add("пам'ять");

        if (_sealOut || _sealIn || _sealMem)
            Ui.Line("   [зашифровано] відкрити зможе лише наш сервер (ключ "
                    + SealKey.KeyId + ").", Ui.Sev.Good);
        if (open.Count > 0)
        {
            Ui.Line("   [!] БЕЗ шифрування: " + string.Join(", ", open.ToArray())
                    + ". Поводьтеся з цими файлами як з відкритими даними;", Ui.Sev.Warn);
            Ui.Note("       причина для кожного - у collection_gaps.csv (найчастіше бракує"
                    + " місця на диску для другої копії файлу).");
        }
    }'''
assert OLD3 in s, 'helper anchor not found'
s = s.replace(OLD3, NEW3, 1)

io.open(P, 'w', encoding='utf-8-sig', newline='\r\n').write(s.replace('\r\n', '\n'))
print('Steps.cs wired: SealArchive for all three archives + an honest closing report')
