# -*- coding: utf-8 -*-
"""Make the sealed container understandable to the person who opens it.

The owner's objection, and it is right: an investigator double-clicks the output archive and
sees "payload.bin" with no explanation. That reads as either a mistake or something
suspicious. The evidence must stay unreadable; the CONTAINER must not.

So: every member gets a name that says what it is, and a README.txt in Ukrainian - first in
the list - explains what this file is, that there is nothing to do with it by hand, and why
the insides look like noise.

The member names now travel in the manifest (`parts`), so the bot resolves them by ROLE
instead of by a hardcoded string, and a future rename costs nothing. Scheme goes to
dfir-enc-3 because the layout changed - my own rule from yesterday: an older bot must refuse
a newer container rather than half-read it.

File names stay ASCII on purpose. Explorer's built-in zip viewer has a long history of
mangling non-ASCII entry names depending on the code page - exactly the boxes problem that
already bit the collector console once - and that cannot be verified through piped tooling.
So the names are plain ASCII and the Ukrainian lives in the README's CONTENT, which is UTF-8
and displays correctly in any editor.
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

P = r'C:\DFIR\pybuild\v4\Seal.cs'
shutil.copy2(P, P + '.bak_readable_' + time.strftime('%Y%m%d_%H%M%S'))
s = io.open(P, encoding='utf-8-sig').read()
assert 'ReadmeName' not in s, 'already patched'

# ---- names and scheme -----------------------------------------------------------------
old = '''    public const string Scheme = "dfir-enc-2";
    public const string PayloadName = "payload.bin";
    public const string ManifestName = "MANIFEST.json";
    public const string KeyName = "key.bin";
    public const string PlainShaName = "PLAIN.sha256";'''
new = '''    public const string Scheme = "dfir-enc-3";
    // Names a human can read. They are ASCII because Explorer's zip viewer mangles
    // non-ASCII entry names depending on the code page, and they travel in the manifest
    // (`parts`) so the bot resolves members by role rather than by a hardcoded string.
    public const string PayloadName = "evidence.encrypted";
    public const string ManifestName = "MANIFEST.json";
    public const string KeyName = "encryption-key.bin";
    public const string PlainShaName = "checksum.sha256";
    public const string ReadmeName = "README.txt";'''
assert old in s, 'name constants not found'
s = s.replace(old, new, 1)

# ---- manifest gains `parts` -----------------------------------------------------------
old2 = '''                + "  \\"collector\\": \\"v4\\"\\n"
                + "}\\n";'''
new2 = '''                + "  \\"collector\\": \\"v4\\",\\n"
                + "  \\"parts\\": {\\n"
                + "    \\"payload\\": \\"" + PayloadName + "\\",\\n"
                + "    \\"key\\": \\"" + KeyName + "\\",\\n"
                + "    \\"checksum\\": \\"" + PlainShaName + "\\"\\n"
                + "  }\\n"
                + "}\\n";'''
assert old2 in s, 'manifest tail not found'
s = s.replace(old2, new2, 1)

# ---- README goes in FIRST, so it is the first thing anyone sees ------------------------
old3 = '''                Write(za, ManifestName, manifestBytes);
                Write(za, KeyName, keyBlob);'''
new3 = '''                Write(za, ReadmeName, new UTF8Encoding(false).GetBytes(Readme(innerName)));
                Write(za, ManifestName, manifestBytes);
                Write(za, KeyName, keyBlob);'''
assert old3 in s, 'member writing not found'
s = s.replace(old3, new3, 1)

# ---- Verify() must know about the README ----------------------------------------------
old4 = '''                bool m = false, k = false, p = false, s = false;
                foreach (ZipArchiveEntry e in za.Entries)
                {
                    if (e.FullName == ManifestName) m = e.Length > 0;
                    else if (e.FullName == KeyName) k = e.Length >= 256;
                    else if (e.FullName == PayloadName) p = e.Length > 32;
                    else if (e.FullName == PlainShaName) s = e.Length >= 64;
                }
                return m && k && p && s;'''
new4 = '''                bool m = false, k = false, p = false, s = false, r = false;
                foreach (ZipArchiveEntry e in za.Entries)
                {
                    if (e.FullName == ManifestName) m = e.Length > 0;
                    else if (e.FullName == KeyName) k = e.Length >= 256;
                    else if (e.FullName == PayloadName) p = e.Length > 32;
                    else if (e.FullName == PlainShaName) s = e.Length >= 64;
                    else if (e.FullName == ReadmeName) r = e.Length > 100;
                }
                return m && k && p && s && r;'''
assert old4 in s, 'Verify body not found'
s = s.replace(old4, new4, 1)

# ---- the README text itself ------------------------------------------------------------
old5 = '''    static void SafeDelete(string p) { try { if (File.Exists(p)) File.Delete(p); } catch { } }'''
new5 = '''    static void SafeDelete(string p) { try { if (File.Exists(p)) File.Delete(p); } catch { } }

    /// <summary>
    /// What the person who opens this archive reads. It exists because "payload.bin" with no
    /// explanation reads as a mistake or as something suspicious - and the one thing an
    /// investigator must not do is start repairing the evidence by hand.
    /// </summary>
    static string Readme(string innerName)
    {
        return
"ЦЕ ЗАШИФРОВАНИЙ АРХІВ ДОКАЗІВ\\r\\n" +
"=============================\\r\\n" +
"\\r\\n" +
"Розпаковувати його й щось із ним робити НЕ ПОТРІБНО.\\r\\n" +
"\\r\\n" +
"ЩО РОБИТИ\\r\\n" +
"   Завантажте цей файл у бота цілим, як він є. Бот сам його відкриє.\\r\\n" +
"\\r\\n" +
"ЧОМУ ВСЕРЕДИНІ НЕЗРОЗУМІЛІ ФАЙЛИ\\r\\n" +
"   Докази зашифровані навмисно: щоб їх не прочитав ніхто, крім нашого\\r\\n" +
"   сервера, навіть якщо цей файл загубиться або потрапить у чужі руки.\\r\\n" +
"   Пароля немає і бути не може - ключ, яким це відкривається, існує\\r\\n" +
"   лише на сервері.\\r\\n" +
"\\r\\n" +
"   " + PayloadName + "   самі докази (зашифровані)\\r\\n" +
"   " + KeyName + "  ключ до них, зашифрований на наш сервер\\r\\n" +
"   " + PlainShaName + "     контрольна сума, щоб перевірити цілісність\\r\\n" +
"   " + ManifestName + "       службовий опис: версія, дата, розмір\\r\\n" +
"\\r\\n" +
"ЯКЩО БОТ КАЖЕ, ЩО НЕ МОЖЕ ВІДКРИТИ АРХІВ\\r\\n" +
"   Не виправляйте нічого самі й не розпаковуйте. Надішліть цей файл\\r\\n" +
"   і текст помилки адміністраторові - помилка називає причину.\\r\\n" +
"\\r\\n" +
"---------------------------------------------------------------\\r\\n" +
"Усередині:  " + innerName + "\\r\\n" +
"Зібрано:    " + DateTime.Now.ToString("yyyy-MM-dd HH:mm") + "\\r\\n" +
"Збирач:     " + Ui.VER + "\\r\\n" +
"Ключ:       " + SealKey.KeyId + "\\r\\n" +
"Схема:      " + Scheme + "\\r\\n";
    }'''
assert old5 in s, 'SafeDelete anchor not found'
s = s.replace(old5, new5, 1)

# ---- the header comment must describe what the file now does --------------------------
s = s.replace('// CONTAINER  "dfir-enc-2"   (a valid STORED zip, written in ONE streaming pass)',
              '// CONTAINER  "dfir-enc-3"   (a valid STORED zip, written in ONE streaming pass)', 1)
s = s.replace('''//   MANIFEST.json   scheme, key id, algorithms, inner archive name and size, timestamp
//   key.bin         RSA-4096-OAEP-SHA256 over 80 bytes: AES key | HMAC key | IV
//   payload.bin     AES-256-CBC(PKCS7) of the archive, then its HMAC-SHA256 (32 B) appended
//   PLAIN.sha256    SHA-256 of the archive BEFORE encryption, so the bot can prove what it
//                   recovered is exactly what we packed''',
'''//   README.txt          Ukrainian: what this file is, that nothing is to be done by hand,
//                       and why the insides look like noise. FIRST in the listing.
//   MANIFEST.json       scheme, key id, algorithms, inner archive name and size, timestamp,
//                       and `parts` - the member names, so the bot resolves them by role
//   encryption-key.bin  RSA-4096-OAEP-SHA256 over 80 bytes: AES key | HMAC key | IV
//   evidence.encrypted  AES-256-CBC(PKCS7) of the archive, then its HMAC-SHA256 (32 B)
//   checksum.sha256     SHA-256 of the archive BEFORE encryption, so the bot can prove what
//                       it recovered is exactly what we packed''', 1)
s = s.replace('''//     openssl enc -d -aes-256-cbc -K <hex> -iv <hex> -in payload.bin -out archive.zip
//   recovers the archive (drop the last 32 bytes of payload.bin, which are the HMAC).''',
'''//     openssl enc -d -aes-256-cbc -K <hex> -iv <hex> -in evidence.encrypted -out archive.zip
//   recovers the archive (drop the last 32 bytes of it, which are the HMAC).''', 1)
s = s.replace('''//             -pkeyopt rsa_oaep_md:sha256 -in key.bin -out keymat.bin''',
              '''//             -pkeyopt rsa_oaep_md:sha256 -in encryption-key.bin -out keymat.bin''', 1)

io.open(P, 'w', encoding='utf-8-sig', newline='\r\n').write(s.replace('\r\n', '\n'))
print('Seal.cs: readable member names, README.txt first, manifest carries `parts`, scheme -> dfir-enc-3')
