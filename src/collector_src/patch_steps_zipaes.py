# -*- coding: utf-8 -*-
"""Збирач шифрує сам — пароль більше не проходить командним рядком.

Останнє, що лишалося від попередньої схеми: `7za a -p<пароль>`. Командні рядки пишуть
Sysmon (подія 1), Security 4688 з аудитом і будь-який EDR — саме на машинах, де працює
збирач. Тепер архіви пише `ZipAes.Create` у цьому ж процесі: формат той самий (WinZip
AES-256, AE-2), 7-Zip і бот читають його як і раніше, але пароль ніде не зʼявляється.

7za лишається — ним і далі дописуються в архів README та загорнутий пароль. Там пароля
немає: це звичайне додавання двох незашифрованих файлів.

Перевірено перед вмонтуванням: 7-Zip читає наш архів («AES-256 Deflate»), розпаковує
байт-у-байт, бот відкриває його своїм кодом, а на 4,6 ГБ проходить межу Zip64 (де перша
версія й зламалася: заголовок переписувався довшим і затирав початок даних).
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
shutil.copy2(P, P + '.bak_zipaes_' + time.strftime('%Y%m%d_%H%M%S'))
s = io.open(P, encoding='utf-8-sig').read()
assert 'ZipAes.Create' not in s, 'already wired'

# ---- архів для бота і архів сирих даних ------------------------------------------------
OLD = '''            string pwIn = Seal.NewPassword(), pwOut = Seal.NewPassword();
            Runner.Run(sevenZa, "a -tzip -mx=1 -mem=AES256 -p" + pwIn + " \\"" + zipIn + "\\" \\"*\\"",
                       inDir, log, "3/4", "Пакування сирих даних", 0);
            AttachKey(zipIn, pwIn, sevenZa, log, "архів сирих даних", ref _sealIn);
            // timing written before the output zip so it is inside it
            Eta.WriteCsv(Path.Combine(outDir, "_collector_timing.csv"));
            Runner.Run(sevenZa, "a -tzip -mx=5 -mem=AES256 -p" + pwOut + " \\"" + zipOut + "\\" \\"*\\"",
                       outDir, log, "4/4", "Пакування розпарсеного", 0);
            AttachKey(zipOut, pwOut, sevenZa, log, "архів для бота", ref _sealOut);'''
NEW = '''            string pwIn = Seal.NewPassword(), pwOut = Seal.NewPassword();
            PackEncrypted(inDir, zipIn, pwIn, "3/4", "Пакування сирих даних");
            AttachKey(zipIn, pwIn, sevenZa, log, "архів сирих даних", ref _sealIn);
            // timing written before the output zip so it is inside it
            Eta.WriteCsv(Path.Combine(outDir, "_collector_timing.csv"));
            PackEncrypted(outDir, zipOut, pwOut, "4/4", "Пакування розпарсеного");
            AttachKey(zipOut, pwOut, sevenZa, log, "архів для бота", ref _sealOut);'''
assert OLD in s, 'packing block not found'
s = s.replace(OLD, NEW, 1)

# ---- архів памʼяті ---------------------------------------------------------------------
OLD2 = '''        string mx = compress ? "-mx=5" : "-mx=0";
        string pw = Seal.NewPassword();
        int rc = 0;
        if (haveDump)
            rc |= Runner.Run(sevenZa, "a -tzip " + mx + " -mem=AES256 -p" + pw + " \\"" + zip
                             + "\\" \\"" + ramDump + "\\"",
                             dir, log, "5/5", "Пакування дампа пам'яті", 0);
        if (haveFiles)
            rc |= Runner.Run(sevenZa, "a -tzip " + mx + " -mem=AES256 -p" + pw + " \\"" + zip + "\\" \\"*\\"",
                             memDir, log, "5/5", "Пакування файлів пам'яті", 0);

        if (!File.Exists(zip)) { Gap("архів пам'яті", "7za повернув код " + rc); return null; }'''
NEW2 = '''        string pw = Seal.NewPassword();
        // Дамп і файли памʼяті - в ОДИН прохід: наш архіватор пише архів цілком, а не
        // дописує до наявного. Дамп додається окремим файлом поруч із деревом memDir.
        string extra = (haveDump && File.Exists(ramDump)) ? ramDump : null;
        string zerr = null;
        Ui.ProgressStart("5/5", "Пакування пам'яті", TimeSpan.Zero);
        DateTime zt0 = DateTime.Now;
        zerr = ZipAes.Create(zip, haveFiles ? memDir : Path.GetDirectoryName(ramDump), pw,
                             extra, null);
        Ui.ProgressDone("5/5", "Пакування пам'яті", DateTime.Now - zt0, zerr == null);

        if (zerr != null || !File.Exists(zip)) { Gap("архів пам'яті", zerr ?? "архів не створено"); return null; }'''
assert OLD2 in s, 'memory packing block not found'
s = s.replace(OLD2, NEW2, 1)

# ---- сам помічник ----------------------------------------------------------------------
OLD3 = '''    /// <summary>Which archives carry a recoverable password - for an honest closing report.</summary>
    static bool _sealOut, _sealIn, _sealMem;'''
NEW3 = '''    /// <summary>Which archives carry a recoverable password - for an honest closing report.</summary>
    static bool _sealOut, _sealIn, _sealMem;

    /// <summary>
    /// Запакувати теку у зашифрований архів НАШИМ кодом: пароль лишається в памʼяті процесу
    /// і не потрапляє в жоден командний рядок (а отже ні в Sysmon, ні в 4688, ні в EDR).
    /// Формат - той самий WinZip AES-256, який відкриває звичайний 7-Zip.
    /// </summary>
    static void PackEncrypted(string srcDir, string zipPath, string password,
                              string phase, string label)
    {
        DateTime t0 = DateTime.Now;
        Ui.ProgressStart(phase, label, Eta.Expected(phase));
        long lastBeat = 0;
        string err = ZipAes.Create(zipPath, srcDir, password, null, delegate (long d, long t)
        {
            if (d - lastBeat > (256L << 20)) { lastBeat = d; }
        });
        Ui.ProgressDone(phase, label, DateTime.Now - t0, err == null);
        Eta.Done(phase, DateTime.Now - t0, err == null);
        if (err != null) Gap(label, err);
    }'''
assert OLD3 in s, 'helper anchor not found'
s = s.replace(OLD3, NEW3, 1)

io.open(P, 'w', encoding='utf-8-sig', newline='\r\n').write(s.replace('\r\n', '\n'))
print('Steps.cs: archives are written by our own encryptor; no password on any command line')
