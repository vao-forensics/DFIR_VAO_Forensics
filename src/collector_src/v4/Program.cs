// DFIR Triage Collector v4 - single native executable, no cmd.exe, no .bat, no .ps1 files.
//
// v3 was: [C# launcher] -> cmd.exe -> Run_KAPE_DFIR.bat -> 13 PowerShell scripts.
// On 2026-08-13 that chain broke on a real ransomware case: Group Policy blocks .ps1 files,
// and -ExecutionPolicy Bypass does NOT override a policy-scoped setting. The operator got an
// error message pasted into the drive-letter variable and an endless retry loop.
//
// v4 keeps only real executables in the chain (kape.exe, EZ Tools, our vao_* tools, 7za) -
// ExecutionPolicy does not apply to those. Anything still written in PowerShell is fed to
// powershell.exe through STDIN, which is command text rather than a script file and runs even
// under a Restricted policy (verified 2026-08-13).

using System;
using System.Collections.Generic;
using System.IO;

class Config
{
    public string Scen = "1";        // 1 LIVE, 2 IMAGE
    public string Mode = "1";        // 1 FAST, 2 FULL, 3 QUIET
    public string Memory = "1";      // LIVE: 1 none 2 files 3 dump+files 4 process dumps
                                     // IMAGE: 1 none 2 files-from-image
    public string RamDest = null;    // where a full RAM dump is written (never the case zip)
    public string Comms = "1";       // 1 no, 2 yes
    public string Drive = "C";
    public string Case = "";
    public bool DryRun;

    public bool Live { get { return Scen == "1"; } }
    public bool Full { get { return Mode == "2"; } }
    public bool Quiet { get { return Mode == "3"; } }
    public bool WantMemFiles { get { return Memory == "2" || Memory == "3"; } }
    public bool WantRamDump { get { return Live && Memory == "3"; } }
    public bool WantProcDumps { get { return Live && Memory == "4"; } }

    public string ModeLabel
    {
        get { return Mode == "2" ? "FULL" : Mode == "3" ? "ТИХИЙ" : "FAST"; }
    }
    public string MemLabel
    {
        get
        {
            if (Memory == "1") return "не збирати";
            if (Memory == "2") return Live ? "файли пам'яті з диска" : "файли пам'яті з образу";
            if (Memory == "3") return "дамп RAM + файли пам'яті  ->  " + (RamDest ?? "?");
            if (Memory == "4") return "дампи окремих процесів";
            return "?";
        }
    }
}

static class Program
{
    static int Main(string[] argv)
    {
        // Long paths, before ANY System.IO call: legacy path handling (the default for an
        // assembly that does not declare 4.6.2+) rejects paths over MAX_PATH and the \\?\
        // prefix alike. See Lp.cs for why this exists.
        try
        {
            AppContext.SetSwitch("Switch.System.IO.UseLegacyPathHandling", false);
            AppContext.SetSwitch("Switch.System.IO.BlockLongPaths", false);
        }
        catch { }

        // Unattended switches. They exist so the whole pipeline can be regression-tested
        // without a human at the keyboard - v3 needed a hand-patched copy of the .bat for
        // every test run, which is how a stale copy once shipped inside the released exe.
        Config cfg = new Config();
        bool auto = false;
        for (int i = 0; i < argv.Length; i++)
        {
            string a = argv[i].ToLowerInvariant();
            string v = (i + 1 < argv.Length) ? argv[i + 1] : null;
            if (a == "--dryrun") cfg.DryRun = true;
            else if (a == "--yes") auto = true;
            else if (a == "--scen" && v != null) { cfg.Scen = v; i++; }
            else if (a == "--mode" && v != null) { cfg.Mode = v; i++; }
            else if (a == "--mem" && v != null) { cfg.Memory = v; i++; }
            else if (a == "--comms" && v != null) { cfg.Comms = v; i++; }
            else if (a == "--drive" && v != null) { cfg.Drive = v; i++; }
            else if (a == "--case" && v != null) { cfg.Case = v; i++; }
            else if (a == "--ramdest" && v != null) { cfg.RamDest = v; i++; }
        }

        Ui.Setup();
        Ui.Banner();

        Env env = new Env();
        env.Probe();
        env.Render();

        EncResult enc = Crypto.Detect();
        RenderEncryption(enc);

        if (!env.IsAdmin)
        {
            Console.WriteLine();
            Ui.Line("   [X] Немає прав адміністратора. Більшість артефактів зібрати неможливо.",
                    Ui.Sev.Bad);
            Ui.Note("       Закрийте це вікно і запустіть файл через праву кнопку ->");
            Ui.Note("       \"Запуск від імені адміністратора\".");
            Ui.Pause("Enter для виходу...");
            return 1;
        }

        if (auto)
        {
            Ui.Unattended = true;
            if (cfg.Case.Length == 0) cfg.Case = Environment.MachineName;
            cfg.Case = SafeCase(cfg.Case);
            Console.WriteLine();
            Ui.Line("   [auto] без запитань: SCEN=" + cfg.Scen + " MODE=" + cfg.Mode
                    + " MEM=" + cfg.Memory + " COMMS=" + cfg.Comms + " DRV=" + cfg.Drive
                    + " CASE=" + cfg.Case, Ui.Sev.Warn);
            if (!Drives.Exists(cfg.Drive))
            {
                Ui.Line("   [X] Диск " + cfg.Drive + ": недоступний.", Ui.Sev.Bad);
                return 1;
            }
            return cfg.DryRun ? 0 : Steps.Run(cfg, env, enc);
        }

        // Whatever the operator must not forget travels in the header of every later screen.
        List<string> st = new List<string>();
        if (enc.Risk == "HIGH") { st.Add("ШИФРУВАННЯ АКТИВНЕ і розблоковане - НЕ вимикайте ПК"); Ui.StatusSev = Ui.Sev.Bad; }
        else if (enc.Risk == "UNKNOWN") { st.Add("стан шифрування НЕ ПЕРЕВІРЕНО"); Ui.StatusSev = Ui.Sev.Warn; }
        else if (enc.Risk == "MED") { st.Add("є ознаки шифрування"); Ui.StatusSev = Ui.Sev.Warn; }
        if (env.CmdState != "OK" || env.PsFileState != "OK")
        {
            st.Add("обмеження запуску програм зафіксовано у справі");
            if (Ui.StatusSev == Ui.Sev.Plain) Ui.StatusSev = Ui.Sev.Warn;
        }
        if (env.ThirdPartyAv)
        {
            st.Add("сторонній антивірус активний");
            if (Ui.StatusSev == Ui.Sev.Plain) Ui.StatusSev = Ui.Sev.Warn;
        }
        Ui.Status = string.Join("   |   ", st.ToArray());

        // ---- 1. scenario ----------------------------------------------------------
        cfg.Scen = Ui.Ask("[ 1 ]  СЦЕНАРІЙ",
            new string[] { "1", "2" },
            new string[] {
                "LIVE   - жива система, що працює зараз\nзбір із запущеної ОС + знімок стану + пам'ять",
                "IMAGE  - змонтований образ диска (офлайн, вже на літері диска)\nтільки дискові артефакти, без стану цієї машини"
            }, "1");

        Ui.ClearBeforeQuestion = true;       // from here on every question owns the screen
        Ui.Crumb(cfg.Live ? "LIVE" : "IMAGE");
        if (!cfg.Live)
        {
            ImageNotice(enc);
            Ui.Pause("Enter, щоб продовжити...");
        }

        // ---- 2. depth -------------------------------------------------------------
        // Quiet mode exists because a third-party AV quarantines THOR/NirSoft-class tools
        // mid-run, which leaves a half-collected case that looks complete.
        string depthDef = env.ThirdPartyAv ? "3" : "1";
        cfg.Mode = Ui.Ask("[ 2 ]  ГЛИБИНА",
            new string[] { "1", "2", "3" },
            new string[] {
                "FAST  - швидко (хвилини): артефакти + типовий розбір\nжурнали, реєстр, запуск програм, MFT/USN, браузери, RDP, MOTW",
                "FULL  - глибоко: усе з FAST плюс sigma-полювання, THOR, RegRipper, ASEP",
                "ТИХИЙ - як FAST, але без інструментів, на які лається сторонній антивірус"
                    + (env.ThirdPartyAv ? "\nрекомендовано: виявлено сторонній антивірус" : "")
            }, depthDef);

        Ui.Crumb(cfg.ModeLabel);

        // ---- 3. memory ------------------------------------------------------------
        long memFiles = Memory.EstimateFilesBytes(cfg.Drive, env.RamBytes);
        string memAdds = memFiles > 0 ? "  (додасть до архіву ~" + Ui.Gb(memFiles) + " ГБ)" : "";

        if (cfg.Live)
        {
            string ramGb = env.RamBytes > 0 ? Ui.Gb(env.RamBytes) + " ГБ" : "невідомо";
            cfg.Memory = Ui.Ask("[ 3 ]  ОПЕРАТИВНА ПАМ'ЯТЬ                                        [ LIVE ]",
                new string[] { "1", "2", "3", "4" },
                new string[] {
                    "Не збирати",
                    "Тільки файли пам'яті з диска                        ризик: НЕМАЄ\n"
                        + "pagefile.sys, swapfile.sys, hiberfil.sys, Minidump" + memAdds,
                    "Дамп RAM + файли пам'яті                            ризик: керований\n"
                        + "обсяг дампа = обсяг пам'яті (тут " + ramGb + "), спитаю куди писати\n"
                        + (enc.Risk == "HIGH"
                            ? "РЕКОМЕНДОВАНО: диск зашифровано і зараз розблоковано - ключі лише в пам'яті"
                            : "потрібно, якщо диск зашифровано або підозра на безфайлову шкідливість"),
                    "Тільки дампи окремих процесів                       ризик: НЕМАЄ\nбез драйвера - для критичних серверів, які не можна ризикувати"
                }, enc.Risk == "HIGH" ? "3" : "1");

            if (cfg.Memory == "3") cfg.RamDest = AskRamDestination(env.RamBytes);
            if (cfg.Memory == "3" && cfg.RamDest == null)
            {
                Ui.Line("   Дамп RAM скасовано - лишаю тільки файли пам'яті.", Ui.Sev.Warn);
                cfg.Memory = "2";
            }
        }
        else
        {
            cfg.Memory = Ui.Ask("[ 3 ]  СЛІДИ ПАМ'ЯТІ НА ДИСКУ                                   [ IMAGE ]",
                new string[] { "1", "2" },
                new string[] {
                    "Не збирати",
                    "Зібрати з ОБРАЗУ                                    ризик: НЕМАЄ\n"
                        + "hiberfil.sys, pagefile.sys, swapfile.sys, Minidump" + memAdds + "\n"
                        + "hiberfil - це ПОВНИЙ зліпок пам'яті: бот розбирає його\n"
                        + "як звичайний дамп, тож аналіз пам'яті ви все одно отримаєте\n"
                        + "БЕРІТЬ, якщо потрібен аналіз пам'яті ботом - інакше це зайві ГБ"
                }, "1");
            Console.WriteLine();
            Ui.Line("      [!] Дампа RAM тут немає і бути не може: в образі пам'яті не існує.", Ui.Sev.Warn);
            Ui.Note("          Спроба зняти її захопила б пам'ять машини СЛІДЧОГО.");
        }
        Ui.Crumb("пам'ять: " + cfg.MemLabel);

        // ---- 4. mail and messengers ----------------------------------------------
        cfg.Comms = Ui.Ask("[ 4 ]  ПОШТА І МЕСЕНДЖЕРИ",
            new string[] { "1", "2" },
            new string[] {
                "Ні - швидко, звичайний розмір архіву",
                "Так - Outlook (.ost/.pst), Thunderbird, Telegram, WhatsApp,\nSignal, Viber, Skype, Discord. Обсяг виміряю до збору."
            }, "1");

        Ui.Crumb(cfg.Comms == "2" ? "з поштою" : "без пошти");

        // ---- 5. drive and case ----------------------------------------------------
        Ui.Screen();
        Ui.Section("[ 5 ]  ЩО ЗБИРАЄМО");
        cfg.Drive = AskDrive(cfg.Live);
        if (cfg.Drive == null) return 1;
        cfg.Case = SafeCase(Ui.AskText("Назва справи", Environment.MachineName));

        // ---- confirmation ---------------------------------------------------------
        if (!Confirm(cfg, env, enc)) { Ui.Pause("Скасовано. Enter для виходу..."); return 0; }

        if (cfg.DryRun)
        {
            Console.WriteLine();
            Ui.Line("   [dryrun] Меню пройдено, збір не запускається.", Ui.Sev.Warn);
            Console.WriteLine("   SCEN=" + cfg.Scen + " MODE=" + cfg.Mode + " MEM=" + cfg.Memory
                + " RAMDEST=" + (cfg.RamDest ?? "-") + " COMMS=" + cfg.Comms
                + " DRV=" + cfg.Drive + " CASE=" + cfg.Case
                + " ENCRISK=" + enc.Risk + " PSFILE=" + env.PsFileState + " PSSTDIN=" + env.PsStdinState);
            return 0;
        }

        return Steps.Run(cfg, env, enc);
    }

    // ---- encryption panel ---------------------------------------------------------
    static void RenderEncryption(EncResult e)
    {
        Ui.Section("[ 0.1 ]  ШИФРУВАННЯ ЦІЄЇ МАШИНИ   (не образу)");
        Row("BitLocker", e.BlState, e.Bl, e.BlWhy);
        Row("VeraCrypt", e.VcState, e.Vc, e.VcWhy);
        Row("Інші FDE", e.FdeState, e.Fde, e.FdeWhy);
        Row("Бут-сектор", e.RawState, e.Raw, e.RawWhy);
        Console.WriteLine("   " + new string('-', 60));

        switch (e.Risk)
        {
            case "HIGH":
                Ui.Line("      [!] ШИФРУВАННЯ АКТИВНЕ і зараз РОЗБЛОКОВАНЕ.", Ui.Sev.Bad);
                Ui.Note("          Ключі є в оперативній пам'яті ЛИШЕ поки ПК увімкнений.");
                Ui.Note("          НЕ вимикайте і НЕ перезавантажуйте цю машину.");
                Ui.Note("          Спершу цей тріаж, потім захоплення пам'яті.");
                break;
            case "MED":
                Ui.Line("      [!] Є ознаки шифрування - перевірте до вимкнення ПК.", Ui.Sev.Warn);
                break;
            case "UNKNOWN":
                Ui.Line("      [!] ПЕРЕВІРКУ НЕ ВИКОНАНО - стан шифрування невідомий.", Ui.Sev.Bad);
                Ui.Note("          Не вимикайте машину, доки не переконаєтесь особисто.");
                break;
            default:
                Ui.Line("      [OK] Ознак шифрування не виявлено.", Ui.Sev.Good);
                if (e.AnyNotRun)
                    Ui.Line("      [!] Але частина перевірок не виконалась - див. рядки \"не перевірено\".",
                            Ui.Sev.Warn);
                break;
        }
    }

    static void Row(string label, Probe st, string val, string why)
    {
        if (st == Probe.Detected) Ui.Field(label, val, Ui.Sev.Bad);
        else if (st == Probe.Clean) Ui.Field(label, "не виявлено", Ui.Sev.Good);
        else Ui.Field(label, "НЕ ПЕРЕВІРЕНО" + (why.Length > 0 ? " - " + why : ""), Ui.Sev.Warn);
    }

    static void ImageNotice(EncResult e)
    {
        Console.WriteLine();
        Console.WriteLine("   " + new string('=', 60));
        Console.WriteLine("        РЕЖИМ ОБРАЗУ - ЩО ЦЕ ЗМІНЮЄ");
        Console.WriteLine("   " + new string('-', 60));
        Ui.Note("[!] Дані про шифрування вище стосуються ЦІЄЇ робочої");
        Ui.Note("    станції, а НЕ образу. У справу вони НЕ потрапляють.");
        Ui.Note("[!] Оперативна пам'ять НЕ збирається: в образі її немає.");
        Ui.Note("[+] pagefile / hiberfil / swapfile беруться З ОБРАЗУ.");
        Console.WriteLine("   " + new string('=', 60));
    }

    // ---- drive selection ----------------------------------------------------------
    // v3 looped here forever when PowerShell failed and the error text became the answer.
    // Here the letter is validated in-process and the loop is bounded.
    static string AskDrive(bool live)
    {
        string def = live ? "C" : null;
        for (int attempt = 0; attempt < 5; attempt++)
        {
            string ans = Ui.AskText(live ? "Диск для збору" : "Літера змонтованого образу (напр. E)", def);
            string d = Drives.Normalize(ans);
            if (d != null && Drives.Exists(d)) return d;
            Ui.Line("   [X] Диск \"" + (ans ?? "") + "\" недоступний. Наявні: " + Drives.ListLetters(), Ui.Sev.Warn);
        }
        Ui.Line("   [X] Диск не обрано.", Ui.Sev.Bad);
        Ui.Pause("Enter для виходу...");
        return null;
    }

    static string AskRamDestination(long ramBytes)
    {
        long need = (ramBytes > 0 ? ramBytes : 8L * 1073741824L) + 1073741824L;  // +1 GB margin
        Ui.Section("КУДИ ПИСАТИ ДАМП ПАМ'ЯТІ");
        Ui.Note("Потрібно щонайменше " + Ui.Gb(need) + " ГБ. У архів для бота дамп НЕ входить.");
        Ui.Note("Найкраще - зовнішній диск, щоб не чіпати доказовий носій.");
        Console.WriteLine();

        List<DriveInfo> ok = new List<DriveInfo>();
        foreach (DriveInfo di in Drives.Writable())
        {
            bool fits = di.AvailableFreeSpace >= need;
            string tag = fits ? "     " : "  --- ";
            Console.WriteLine(tag + di.Name.TrimEnd('\\').PadRight(4)
                + Ui.Trunc(di.DriveType.ToString(), 12)
                + " вільно " + Ui.Gb(di.AvailableFreeSpace).PadLeft(7) + " ГБ"
                + (fits ? "" : "   (замало)"));
            if (fits) ok.Add(di);
        }
        Console.WriteLine();
        if (ok.Count == 0)
        {
            Ui.Line("   [X] Немає диска з достатнім вільним місцем.", Ui.Sev.Bad);
            return null;
        }
        for (int attempt = 0; attempt < 5; attempt++)
        {
            string ans = Ui.AskText("Літера диска для дампа (порожньо - скасувати)", null);
            if (ans == null || ans.Trim().Length == 0) return null;
            string d = Drives.Normalize(ans);
            foreach (DriveInfo di in ok)
                if (d != null && di.Name.StartsWith(d, StringComparison.OrdinalIgnoreCase))
                    return d + @":\";
            Ui.Line("   Оберіть одну з літер, що мають достатньо місця.", Ui.Sev.Warn);
        }
        return null;
    }

    static string SafeCase(string s)
    {
        if (string.IsNullOrEmpty(s)) s = Environment.MachineName;
        char[] bad = Path.GetInvalidFileNameChars();
        System.Text.StringBuilder sb = new System.Text.StringBuilder();
        foreach (char c in s)
            sb.Append(c == ' ' ? '_' : (Array.IndexOf(bad, c) >= 0 ? '_' : c));
        string r = sb.ToString().Trim('_');
        return r.Length == 0 ? Environment.MachineName : r;
    }

    // ---- confirmation screen -------------------------------------------------------
    static bool Confirm(Config c, Env env, EncResult enc)
    {
        Ui.Crumbs.Clear();          // the confirmation screen lists everything in full
        Ui.Screen();
        Ui.Section("ПЕРЕВІРТЕ ПЕРЕД ЗАПУСКОМ");
        Ui.Field("Сценарій", c.Live ? "LIVE (жива система)" : "IMAGE (змонтований образ)", Ui.Sev.Plain);
        Ui.Field("Глибина", c.ModeLabel, Ui.Sev.Plain);
        Ui.Field("Диск", c.Drive + ":", Ui.Sev.Plain);
        Ui.Field("Справа", c.Case, Ui.Sev.Plain);
        Ui.Field("Пам'ять", c.MemLabel, c.Memory == "1" ? Ui.Sev.Unknown : Ui.Sev.Plain);
        Ui.Field("Пошта/месенджери", c.Comms == "2" ? "так" : "ні", Ui.Sev.Plain);
        if (!env.PsUsable)
            Ui.Field("Увага", "PowerShell недоступний - частину перевірок буде пропущено", Ui.Sev.Warn);
        if (enc.Risk == "HIGH" && !c.WantRamDump && c.Live)
            Ui.Field("Увага", "диск розблоковано, але дамп пам'яті не обрано", Ui.Sev.Warn);
        // Say up front how many archives come out and roughly how big. Forty-eight
        // gigabytes should never be a surprise discovered after an hour of work.
        long memEst = c.WantMemFiles ? Memory.EstimateFilesBytes(c.Drive, env.RamBytes) : 0;
        if (c.WantRamDump && env.RamBytes > 0) memEst += env.RamBytes;
        Console.WriteLine();
        Ui.Note("На виході:");
        Ui.Note("   " + c.Case + "_output.zip   ~100 МБ   -> головний, у бота на аналіз");
        if (memEst > 0)
            Ui.Note("   " + c.Case + "_memory.zip   ~" + Ui.Gb(memEst)
                    + " ГБ   -> окремо, кнопка \"RAM Memory\"");
        Ui.Note("   " + c.Case + "_input.zip    сирі артефакти");
        if (memEst > 32L * 1073741824L)
            Ui.Line("      [!] Пам'ять перевищує ліміт завантаження в бота (32 ГБ).", Ui.Sev.Warn);

        Console.WriteLine();
        string a = Ui.AskText("[Enter] почати   [З] змінити   [Q] вийти", "");
        if (a == null) return true;
        a = a.Trim().ToUpperInvariant();
        if (a == "Q" || a == "Й") return false;
        if (a == "З" || a == "Z" || a == "P" || a == "П")
        {
            Console.WriteLine();
            Ui.Line("   Перезапустіть збирач, щоб змінити відповіді.", Ui.Sev.Warn);
            return false;
        }
        return true;
    }
}
