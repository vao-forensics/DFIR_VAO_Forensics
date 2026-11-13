// Пише ZIP із шифруванням WinZip AES-256 (AE-2) — власним кодом, без зовнішнього архіватора.
//
// НАВІЩО ЦЕ ІСНУЄ
//   Єдина слабина попередньої схеми: 7za бере пароль у КОМАНДНОМУ РЯДКУ, а командні рядки
//   пишуть Sysmon (подія 1), Security 4688 з аудитом і будь-який EDR — саме на тих машинах,
//   де працює збирач. Хто потім має і логи машини, і архів, той архів відкриє. Перевірено:
//   зі stdin 7za пароль не бере («The parameter is incorrect»), тож усередині 7za обходу
//   немає. Лишався один шлях — шифрувати самим, у процесі, де пароль ніколи не залишає
//   памʼяті.
//
// ЧОМУ САМЕ ФОРМАТ AE-2, А НЕ ВЛАСНИЙ
//   Власник має могти відкрити архів звичайним 7-Zip і ввести пароль. AE-2 — це те, що
//   7-Zip, WinRAR і провідник Windows розуміють штатно: імена файлів видно, вміст під AES.
//   Формат опублікований, тут він не вгаданий:
//     запис = сіль(16) | перевірка пароля(2) | шифротекст | код автентичності(10)
//     ключі = PBKDF2-HMAC-SHA1(пароль, сіль, 1000) -> 32 шифр | 32 HMAC | 2 перевірка
//     шифр  = AES-CTR, лічильник 16 байтів LITTLE-endian, з одиниці
//     код   = HMAC-SHA1(ключ HMAC, шифротекст), обрізаний до 10 байтів
//     поле 0x9901 у extra: версія 2, вендор "AE", стійкість 3 (AES-256), справжній метод
//   В AE-2 CRC не зберігається (пишеться 0) — саме тому тут немає ще одного проходу даними.
//
// ЧОМУ ЗАПИС РУЧНИЙ
//   ZipArchive у .NET не вміє шифрувати, тому структура пишеться тут: локальний заголовок,
//   дані, центральний каталог, кінцевий запис. Розміри заздалегідь невідомі (стиснення
//   потокове), тому вони вписуються ПІСЛЯ запису — поверненням назад по файлу. Дескриптори
//   даних навмисно не використовуються: вихід — звичайний файл, отже перемотка доступна, а
//   архів без дескрипторів відкривають геть усі читачі.
//
// ZIP64 вмикається автоматично, щойно файл або архів переступає 4 ГБ — інакше архів памʼяті
// на 30 ГБ просто не існував би.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

static class ZipAes
{
    const int SALT_LEN = 16;          // AES-256
    const int KEY_LEN = 32;
    const int MAC_LEN = 10;
    const int VERIFIER_LEN = 2;
    const int PBKDF2_ROUNDS = 1000;
    const ushort AES_METHOD = 99;
    const ushort AES_EXTRA_ID = 0x9901;
    const ushort ZIP64_EXTRA_ID = 0x0001;
    const uint ZIP64_LIMIT = 0xFFFFFFFF;

    /// <summary>Скільки байтів уже оброблено — щоб оператор бачив рух, а не завмерлий екран.</summary>
    public delegate void Progress(long done, long total);

    sealed class Entry
    {
        public string Name;           // імʼя в архіві, зі слешами
        public long Offset;           // де починається локальний заголовок
        public long Compressed;
        public long Uncompressed;
        public ushort Method;         // справжній метод (8 = deflate, 0 = store)
        public DateTime Modified;
        // Вирішується ОДИН раз, за розміром джерела, ще до першого запису заголовка:
        // інакше другий заголовок стає довшим за перший і затирає початок даних
        // (спіймано на архіві 4,6 ГБ).
        public bool Zip64;
    }

    /// <summary>
    /// Запакувати вміст теки в зашифрований архів. Повертає null або причину помилки.
    /// Пароль існує лише як рядок у памʼяті цього процесу.
    /// </summary>
    public static string Create(string zipPath, string rootDir, string password,
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
            string[] files = all.ToArray();

            long total = 0;
            foreach (string f in files)
            {
                try { total += new FileInfo(f).Length; } catch { }
            }
            long done = 0;

            List<Entry> entries = new List<Entry>(files.Length);
            using (FileStream outp = new FileStream(zipPath, FileMode.Create, FileAccess.ReadWrite,
                                                    FileShare.None, 1 << 20))
            {
                foreach (string path in files)
                {
                    // файл поза текою (дамп памʼяті) кладемо під власним іменем
                    string rel = (rootDir != null && path.StartsWith(rootDir,
                                      StringComparison.OrdinalIgnoreCase))
                                 ? path.Substring(rootDir.Length)
                                       .TrimStart('\\', '/').Replace('\\', '/')
                                 : Path.GetFileName(path);
                    Entry e = WriteEntry(outp, path, rel, password, ref done, total, progress);
                    if (e != null) entries.Add(e);
                }
                WriteCentralDirectory(outp, entries);
            }
            if (entries.Count == 0) return "жоден файл не вдалося прочитати";
            return null;
        }
        catch (Exception ex)
        {
            try { if (File.Exists(zipPath)) File.Delete(zipPath); } catch { }
            return Lp.Human(ex);
        }
    }

    static Entry WriteEntry(FileStream outp, string path, string rel, string password,
                            ref long done, long total, Progress progress)
    {
        FileStream fin;
        try { fin = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20); }
        catch { return null; }          // зайнятий файл не має валити весь збір

        using (fin)
        {
            Entry e = new Entry();
            e.Name = rel;
            e.Offset = outp.Position;
            e.Method = 8;               // deflate: архіви доказів інакше вдвічі більші
            long srcLen = 0;
            try { srcLen = fin.Length; } catch { }
            // 0xFFFFF000 - трохи менше за 4 ГБ: запас на службові дані запису й на те,
            // що deflate у найгіршому випадку трохи більший за вхід.
            e.Zip64 = srcLen >= 0xFFFFF000L;
            try { e.Modified = File.GetLastWriteTime(path); } catch { e.Modified = DateTime.Now; }

            byte[] nameBytes = Encoding.UTF8.GetBytes(rel);
            // Локальний заголовок із нульовими розмірами — впишемо їх, коли дізнаємось.
            WriteLocalHeader(outp, e, nameBytes, 0, 0);

            byte[] salt = new byte[SALT_LEN];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider()) rng.GetBytes(salt);
            byte[] encKey, macKey, verifier;
            Derive(password, salt, out encKey, out macKey, out verifier);

            long dataStart = outp.Position;
            outp.Write(salt, 0, salt.Length);
            outp.Write(verifier, 0, verifier.Length);

            long plain = 0;
            byte[] mac;
            using (HMACSHA1 hmac = new HMACSHA1(macKey))
            {
                using (CtrStream ctr = new CtrStream(outp, encKey, hmac))
                using (DeflateStream deflate = new DeflateStream(ctr, CompressionLevel.Optimal, true))
                {
                    byte[] buf = new byte[1 << 20];
                    int n;
                    while ((n = fin.Read(buf, 0, buf.Length)) > 0)
                    {
                        deflate.Write(buf, 0, n);
                        plain += n;
                        done += n;
                        if (progress != null) progress(done, total);
                    }
                }
                hmac.TransformFinalBlock(new byte[0], 0, 0);
                mac = hmac.Hash;
            }
            outp.Write(mac, 0, MAC_LEN);

            e.Uncompressed = plain;
            e.Compressed = outp.Position - dataStart;   // сіль + перевірка + шифротекст + код

            // Повертаємось і вписуємо справжні розміри.
            long after = outp.Position;
            outp.Position = e.Offset;
            WriteLocalHeader(outp, e, nameBytes, e.Compressed, e.Uncompressed);
            outp.Position = after;

            Array.Clear(encKey, 0, encKey.Length);
            Array.Clear(macKey, 0, macKey.Length);
            return e;
        }
    }

    static void Derive(string password, byte[] salt, out byte[] encKey, out byte[] macKey,
                       out byte[] verifier)
    {
        using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(
                   Encoding.UTF8.GetBytes(password), salt, PBKDF2_ROUNDS))
        {
            encKey = kdf.GetBytes(KEY_LEN);
            macKey = kdf.GetBytes(KEY_LEN);
            verifier = kdf.GetBytes(VERIFIER_LEN);
        }
    }

    // ---------------------------------------------------------------- структура ZIP
    static void WriteLocalHeader(FileStream o, Entry e, byte[] nameBytes,
                                 long compressed, long uncompressed)
    {
        bool z64 = e.Zip64;        // рішення вже ухвалене за розміром джерела
        BinaryWriter w = new BinaryWriter(o, Encoding.UTF8, true);
        w.Write((uint)0x04034B50);
        w.Write((ushort)(z64 ? 45 : 51));            // версія: 5.1 для AES, 4.5 для Zip64
        w.Write((ushort)(1 | 0x0800));               // біт 0 - зашифровано, 11 - UTF-8 імена
        w.Write(AES_METHOD);
        w.Write(DosTime(e.Modified));
        w.Write((uint)0);                            // CRC в AE-2 завжди 0
        w.Write((uint)(z64 ? ZIP64_LIMIT : (uint)compressed));
        w.Write((uint)(z64 ? ZIP64_LIMIT : (uint)uncompressed));
        w.Write((ushort)nameBytes.Length);
        w.Write((ushort)(11 + (z64 ? 20 : 0)));      // extra: AES(11) + Zip64(20)
        w.Write(nameBytes, 0, nameBytes.Length);
        WriteAesExtra(w, e.Method);
        if (z64)
        {
            w.Write(ZIP64_EXTRA_ID);
            w.Write((ushort)16);
            w.Write((ulong)uncompressed);
            w.Write((ulong)compressed);
        }
        w.Flush();
    }

    static void WriteAesExtra(BinaryWriter w, ushort realMethod)
    {
        w.Write(AES_EXTRA_ID);
        w.Write((ushort)7);
        w.Write((ushort)2);          // AE-2
        w.Write((byte)'A');
        w.Write((byte)'E');
        w.Write((byte)3);            // AES-256
        w.Write(realMethod);
    }

    static void WriteCentralDirectory(FileStream o, List<Entry> entries)
    {
        long start = o.Position;
        BinaryWriter w = new BinaryWriter(o, Encoding.UTF8, true);
        foreach (Entry e in entries)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(e.Name);
            bool z64 = e.Zip64 || e.Offset > ZIP64_LIMIT;
            w.Write((uint)0x02014B50);
            w.Write((ushort)(z64 ? 45 : 51));
            w.Write((ushort)(z64 ? 45 : 51));
            w.Write((ushort)(1 | 0x0800));
            w.Write(AES_METHOD);
            w.Write(DosTime(e.Modified));
            w.Write((uint)0);
            w.Write((uint)(z64 ? ZIP64_LIMIT : (uint)e.Compressed));
            w.Write((uint)(z64 ? ZIP64_LIMIT : (uint)e.Uncompressed));
            w.Write((ushort)nameBytes.Length);
            w.Write((ushort)(11 + (z64 ? 28 : 0)));
            w.Write((ushort)0);                       // коментар
            w.Write((ushort)0);                       // номер диска
            w.Write((ushort)0);                       // внутрішні атрибути
            w.Write((uint)0);                         // зовнішні атрибути
            w.Write((uint)(z64 ? ZIP64_LIMIT : (uint)e.Offset));
            w.Write(nameBytes, 0, nameBytes.Length);
            WriteAesExtra(w, e.Method);
            if (z64)
            {
                w.Write(ZIP64_EXTRA_ID);
                w.Write((ushort)24);
                w.Write((ulong)e.Uncompressed);
                w.Write((ulong)e.Compressed);
                w.Write((ulong)e.Offset);
            }
        }
        long size = o.Position - start;
        bool needZ64 = entries.Count > 0xFFFE || start > ZIP64_LIMIT || size > ZIP64_LIMIT;
        if (needZ64)
        {
            long z64Eocd = o.Position;
            w.Write((uint)0x06064B50);
            w.Write((ulong)44);
            w.Write((ushort)45);
            w.Write((ushort)45);
            w.Write((uint)0);
            w.Write((uint)0);
            w.Write((ulong)entries.Count);
            w.Write((ulong)entries.Count);
            w.Write((ulong)size);
            w.Write((ulong)start);
            w.Write((uint)0x07064B50);
            w.Write((uint)0);
            w.Write((ulong)z64Eocd);
            w.Write((uint)1);
        }
        w.Write((uint)0x06054B50);
        w.Write((ushort)0);
        w.Write((ushort)0);
        w.Write((ushort)(needZ64 ? 0xFFFF : entries.Count));
        w.Write((ushort)(needZ64 ? 0xFFFF : entries.Count));
        w.Write((uint)(needZ64 ? ZIP64_LIMIT : (uint)size));
        w.Write((uint)(needZ64 ? ZIP64_LIMIT : (uint)start));
        w.Write((ushort)0);
        w.Flush();
    }

    static uint DosTime(DateTime t)
    {
        if (t.Year < 1980) t = new DateTime(1980, 1, 1);
        uint date = (uint)(((t.Year - 1980) << 9) | (t.Month << 5) | t.Day);
        uint time = (uint)((t.Hour << 11) | (t.Minute << 5) | (t.Second / 2));
        return (date << 16) | time;
    }

    /// <summary>
    /// AES-CTR із лічильником, який використовує AE-2: 16 байтів, LITTLE-endian, з одиниці.
    /// Саме через little-endian не годиться штатний CTR більшості бібліотек. Дані на виході
    /// одразу йдуть у HMAC — другий прохід по гігабайтах шифротексту нам не потрібен.
    /// </summary>
    sealed class CtrStream : Stream
    {
        readonly Stream _out;
        readonly HMACSHA1 _mac;
        readonly ICryptoTransform _ecb;
        readonly byte[] _counter = new byte[16];
        readonly byte[] _pad = new byte[16];
        int _padUsed = 16;
        ulong _block = 1;

        public CtrStream(Stream outp, byte[] key, HMACSHA1 mac)
        {
            _out = outp;
            _mac = mac;
            Aes aes = new AesCryptoServiceProvider();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            _ecb = aes.CreateEncryptor();
        }

        void NextPad()
        {
            for (int i = 0; i < 8; i++) _counter[i] = (byte)(_block >> (8 * i));
            for (int i = 8; i < 16; i++) _counter[i] = 0;
            _ecb.TransformBlock(_counter, 0, 16, _pad, 0);
            _block++;
            _padUsed = 0;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            byte[] outBuf = new byte[count];
            for (int i = 0; i < count; i++)
            {
                if (_padUsed >= 16) NextPad();
                outBuf[i] = (byte)(buffer[offset + i] ^ _pad[_padUsed++]);
            }
            _mac.TransformBlock(outBuf, 0, count, null, 0);
            _out.Write(outBuf, 0, count);
        }

        public override void Flush() { _out.Flush(); }
        public override bool CanRead { get { return false; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return true; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }
        public override int Read(byte[] b, int o, int c) { throw new NotSupportedException(); }
        public override long Seek(long o, SeekOrigin w) { throw new NotSupportedException(); }
        public override void SetLength(long v) { throw new NotSupportedException(); }
        protected override void Dispose(bool disposing)
        {
            if (disposing) { try { _ecb.Dispose(); } catch { } }
            // потік назовні НЕ закриваємо: у нього ще дописується код автентичності
        }
    }
}
