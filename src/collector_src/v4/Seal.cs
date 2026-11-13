// Protects the archives the collector produces: a password-protected ZIP (WinZip AES-256)
// whose password only our server can recover.
//
// WHY A PASSWORD ZIP AND NOT OUR OWN FORMAT
//   The owner has to be able to look inside an archive themselves, with ordinary tools. A
//   password-protected ZIP does exactly that: 7-Zip shows the file tree, and the files
//   need a password. Our own cipher would have made the archive readable only by the bot.
//
// WHERE THE PASSWORD COMES FROM AND GOES
//   It is random per archive, 40 characters, generated in process. The EXE carries only the
//   PUBLIC half of an RSA-4096 key (Seal_key.cs, generated at build time from C:\DFIR\keys),
//   so the password is wrapped with that key and written INTO the archive as an unencrypted
//   entry `_dfir_key.bin`. The archive is therefore self-contained: the bot unwraps the
//   password with the private key and opens the archive without anyone typing anything, and
//   the owner recovers the same password with one command on the host. Nobody else can:
//   a public key encrypts and can never decrypt.
//
// THE PASSWORD NEVER TOUCHES A COMMAND LINE (closed in v4.9, 2026-09-19)
//   Up to v4.8 7za packed the evidence with -p<password>, and command lines are recorded by
//   Sysmon (event 1), Security 4688 and every EDR on the very machines this collector runs
//   on. Since v4.9 the evidence is encrypted in-process by ZipAes.cs; 7za only appends the
//   two UNencrypted files below (README, wrapped key) and is never given the password.
//
// WHAT THE ARCHIVE LOOKS LIKE
//   README.txt        unencrypted: what this file is, that nothing is to be done by hand
//   _dfir_key.bin     unencrypted: the password, wrapped for our server
//   everything else   the evidence tree - names visible, contents AES-256
//
// RECOVERY WITHOUT OUR CODE (documented in docs/COLLECTOR_CRYPTO.md):
//   openssl pkeyutl -decrypt -inkey collector_private.pem -pkeyopt rsa_padding_mode:oaep \
//           -pkeyopt rsa_oaep_md:sha256 -in _dfir_key.bin
//   prints the password; then open the archive with 7-Zip as usual.

using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

static class Seal
{
    public const string Scheme = "dfir-pwzip-1";
    public const string KeyName = "_dfir_key.bin";
    public const string ReadmeName = "README.txt";
    /// <summary>Password length in characters. 40 of a 64-symbol alphabet is 240 bits.</summary>
    const int PW_LEN = 40;

    /// <summary>
    /// A fresh password for one archive. Unambiguous alphabet on purpose: the owner may end
    /// up typing this into 7-Zip by hand, and 0/O and 1/l/I are how that goes wrong.
    /// </summary>
    public static string NewPassword()
    {
        const string ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        byte[] raw = new byte[PW_LEN * 2];
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider()) rng.GetBytes(raw);
        StringBuilder sb = new StringBuilder(PW_LEN);
        // rejection sampling, so every character is equally likely
        for (int i = 0; i < raw.Length && sb.Length < PW_LEN; i++)
        {
            int limit = 256 - (256 % ALPHABET.Length);
            if (raw[i] >= limit) continue;
            sb.Append(ALPHABET[raw[i] % ALPHABET.Length]);
        }
        while (sb.Length < PW_LEN) sb.Append(ALPHABET[0]);   // cannot happen; never return short
        return sb.ToString();
    }

    /// <summary>
    /// Put README.txt and the wrapped password into an archive that 7za has just created,
    /// UNENCRYPTED (no -p on this call), so both are readable without the password.
    /// Returns null on success or a reason to record as a gap.
    /// </summary>
    public static string Attach(string sevenZa, string archive, string password, string log)
    {
        string stage = null;
        try
        {
            if (!File.Exists(archive)) return "архіву немає";
            byte[] blob = WrapKey(password);
            if (blob == null) return "не вдалося зашифрувати пароль на наш ключ";

            stage = Path.Combine(Path.GetTempPath(), "dfk_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(stage);
            File.WriteAllBytes(Path.Combine(stage, KeyName), blob);
            File.WriteAllText(Path.Combine(stage, ReadmeName),
                              Readme(Path.GetFileName(archive)), new UTF8Encoding(false));

            int rc = Runner.Run(sevenZa, "a -tzip -mx=0 \"" + archive + "\" \""
                                + Path.Combine(stage, "*") + "\"", stage, log,
                                "seal", "Ключ до архіву", 120000);
            if (rc != 0) return "7za повернув код " + rc;

            // Prove it: the archive must now hold both, and they must be readable.
            using (ZipArchive za = ZipFile.OpenRead(archive))
            {
                bool k = false, r = false;
                foreach (ZipArchiveEntry e in za.Entries)
                {
                    if (e.FullName == KeyName) k = e.Length >= 256;
                    else if (e.FullName == ReadmeName) r = e.Length > 100;
                }
                if (!k) return "ключ не потрапив в архів";
                if (!r) return "README не потрапив в архів";
            }
            return null;
        }
        catch (Exception ex) { return Lp.Human(ex); }
        finally
        {
            if (stage != null) { try { Directory.Delete(stage, true); } catch { } }
        }
    }

    static byte[] WrapKey(string password)
    {
        try
        {
            RSAParameters p = new RSAParameters();
            p.Modulus = Convert.FromBase64String(SealKey.ModulusB64);
            p.Exponent = Convert.FromBase64String(SealKey.ExponentB64);
            using (RSACng rsa = new RSACng())
            {
                rsa.ImportParameters(p);
                return rsa.Encrypt(new UTF8Encoding(false).GetBytes(password),
                                   RSAEncryptionPadding.OaepSHA256);
            }
        }
        catch { return null; }
    }

    /// <summary>
    /// What the person who opens the archive reads. It exists because an unexplained
    /// encrypted archive reads as a mistake or as something suspicious - and the one thing
    /// an investigator must not do is start repairing the evidence by hand.
    /// </summary>
    static string Readme(string archiveName)
    {
        return
"ЦЕ АРХІВ ДОКАЗІВ. ФАЙЛИ В НЬОМУ ПІД ПАРОЛЕМ.\r\n" +
"============================================\r\n" +
"\r\n" +
"Список файлів видно без пароля - щоб було зрозуміло, що зібрано.\r\n" +
"Щоб відкрити самі файли, потрібен пароль.\r\n" +
"\r\n" +
"ЩО РОБИТИ\r\n" +
"   Завантажте цей файл у бота цілим, як він є. Пароль боту вводити\r\n" +
"   не треба - він лежить у цьому ж архіві (" + KeyName + "),\r\n" +
"   зашифрований так, що його читає лише наш сервер.\r\n" +
"\r\n" +
"ЯКЩО ПОТРІБНО ЗАЗИРНУТИ САМОМУ\r\n" +
"   Пароль видає одна команда на нашому хості:\r\n" +
"       show_password.cmd <цей файл>\r\n" +
"   Далі відкривайте архів звичайним 7-Zip і вводьте пароль.\r\n" +
"\r\n" +
"ЧОГО НЕ РОБИТИ\r\n" +
"   Не видаляйте " + KeyName + " з архіву - без нього пароль\r\n" +
"   не відновить ніхто, і докази будуть втрачені назавжди.\r\n" +
"   Не перепаковуйте архів і не намагайтесь щось у ньому виправити.\r\n" +
"\r\n" +
"---------------------------------------------------------------\r\n" +
"Архів:   " + archiveName + "\r\n" +
"Зібрано: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm") + "\r\n" +
"Збирач:  " + Ui.VER + "\r\n" +
"Ключ:    " + SealKey.KeyId + "\r\n" +
"Схема:   " + Scheme + "\r\n";
    }
}
