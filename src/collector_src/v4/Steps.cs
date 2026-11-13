// The collection pipeline. This is what Run_KAPE_DFIR.bat used to be.
//
// Order matters and is not obvious, so it is spelled out:
//   1  KAPE targets   -> input\    (raw artefacts copied off the target disk)
//   2  KAPE modules   -> output\   (parsed CSVs; runs with --mflush, which WIPES output\)
//   2.5 our own analysis and raw copies  -- MUST come after 2, or --mflush deletes them
//   3  zip input, 4 zip output      (output.zip is what the bot ingests)
//
// Every step that cannot run records a row in collection_gaps.csv instead of silently
// producing nothing. A quiet gap is how v3 handed back an archive that looked complete.

using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Text;

static class Steps
{
    static List<string[]> _gaps = new List<string[]>();
    static void Gap(string step, string why)
    {
        _gaps.Add(new string[] { step, why });
        Ui.Line("      [!] пропущено: " + step + " - " + why, Ui.Sev.Warn);
    }

    // EvtxECmd_RDP is gone (2026-09-05). Measured per module on the build host: !EZParser
    // 154 s (its EvtxECmd already parses EVERY event log), and EvtxECmd_RDP another 74 s to
    // parse the same logs a second time through the RDP map - into a second
    // *_EvtxECmd_Output.csv that the bot ingested as ~2x duplicate rows on every case.
    // Dropping it is a third of the modules phase and removes the duplicates.
    const string FAST_MODS = "!EZParser,BrowserParser,NirSoft_WebBrowserDownloads,"
        + "ObsidianForensics_Hindsight,hayabusa_OfflineEventLogs,hayabusa_OfflineLogonSummary,"
        + "ForensicTimeliner,LogParser_LogonLogoffEvents,LogParser_RDPUsageEvents,"
        + "LogParser_SMBServerAnonymousLogons,DHParser,Mplog-Parser,BitsParser";

    // Quiet mode drops the tools a third-party AV reliably quarantines: the NirSoft binaries
    // and the big PyInstaller-packed Hindsight. Nothing is lost from the case - the raw
    // browser databases still travel in _raw\browsers and the bot parses them itself.
    const string QUIET_MODS = "!EZParser,hayabusa_OfflineEventLogs,hayabusa_OfflineLogonSummary,"
        + "ForensicTimeliner,LogParser_LogonLogoffEvents,LogParser_RDPUsageEvents,"
        + "LogParser_SMBServerAnonymousLogons,DHParser,Mplog-Parser,BitsParser";

    const string FULL_MODS = FAST_MODS + ",RegRipper_NTUser,RegRipper_SAM,RegRipper_SECURITY,"
        + "RegRipper_SOFTWARE,RegRipper_SYSTEM,RegRipper_UsrClass,Chainsaw,"
        + "hayabusa_EventStatistics,Thor-Lite_QuickDFIR,reg_hunter_binary,reg_hunter_ip,"
        + "reg_hunter_link,reg_hunter_obfuscation,reg_hunter_script,reg_hunter_shell,"
        + "reg_hunter_suspicious,reg_hunter_unc,reg_hunter_url,RECmd_RegistryASEPs,"
        + "RECmd_SoftwareASEPs,RECmd_SoftwareClassesASEPs,RECmd_SoftwareWoW6432ASEPs,"
        + "RECmd_SystemASEPs,RECmd_UserClassesASEPs,Windows_Hello2Hashcat,LevelDBDumper,TeamsParser";
    // DeepblueCLI intentionally absent: its module runs powershell.exe, which is exactly the
    // dependency v4 exists to remove, and Hayabusa + Chainsaw already cover its detections.
    // PowerShell_Defender_Exclusions and SysInternals_Autoruns are likewise gone - both are
    // reimplemented natively below (Defender.WriteEvidence / Autoruns).

    static string _tool, _workRoot, _log;

    /// <summary>
    /// Wrapper whose only job is to give back the Defender exclusions no matter how the run
    /// ends. An earlier build crashed mid-collection and left its exclusion behind; 16 of
    /// those had piled up on this host before anyone noticed, and on a target machine a stale
    /// exclusion is evidence we would be forging.
    /// </summary>
    public static int Run(Config c, Env env, EncResult enc)
    {
        try { return RunInner(c, env, enc); }
        catch (Exception ex)
        {
            Console.WriteLine();
            Ui.Line("  [X] Збір перервано помилкою: " + Lp.Human(ex), Ui.Sev.Bad);
            Ui.Line("      " + ex.GetType().Name + " @ " + ex.StackTrace, Ui.Sev.Unknown);
            return 2;
        }
        finally
        {
            if (_tool != null) Cleanup(_tool, _workRoot);
        }
    }

    /// <summary>
    /// One failing step must not end the collection. Before 2026-09-05 a PathTooLongException
    /// escaping from a raw-copy helper went to the top-level catch, printed in red and the run
    /// stopped with no archive. Now the failure is a row in collection_gaps.csv and the next
    /// step runs.
    /// </summary>
    static void Guard(string label, Action body)
    {
        try { body(); }
        catch (Exception ex)
        {
            // never append ex.Message for a class we have wording for: .NET localises it
            string why = Lp.Human(ex);
            Gap(label, why);
        }
    }

    static int RunInner(Config c, Env env, EncResult enc)
    {
        Ps.Init(env);
        _gaps.Clear();
        Lp.Reset();
        // the phases this run will go through, so the ETA can say "to the end" not "this step"
        List<string> plan = new List<string>(new string[] { "unpack", "1/4", "2/4", "ps", "exec", "raw", "net" });
        if (c.WantRamDump) plan.Add("RAM");
        plan.Add("footprint"); plan.Add("3/4"); plan.Add("4/4");
        if (c.WantMemFiles || c.WantRamDump) plan.Add("5/5");
        Eta.Plan(plan);

        string workRoot = @"C:\DFIR_Triage";
        string tool = Path.Combine(Path.GetTempPath(),
            "DFIRTriage_" + Guid.NewGuid().ToString("N").Substring(0, 10));
        _tool = tool; _workRoot = workRoot;

        try { Directory.CreateDirectory(workRoot); }
        catch (Exception ex)
        {
            Ui.Line("  [X] Не вдалося створити " + workRoot + ": " + Lp.Human(ex), Ui.Sev.Bad);
            Ui.Pause("Enter для виходу...");
            return 1;
        }

        Ui.Section("ПІДГОТОВКА");
        int purgedDirs = PurgeOwnStaleDirs();
        if (purgedDirs > 0) Ui.Note("прибрано власних тек від перерваних запусків: " + purgedDirs);
        int purged = Defender.PurgeOwnStale();
        if (purged > 0) Ui.Note("знято застарілих власних винятків Defender: " + purged);
        bool exclOk = Defender.Add(workRoot) && Defender.Add(tool);
        Ui.Note(exclOk ? "винятки Defender додано (буде сказано, які зняти в кінці)"
                       : "винятки Defender додати не вдалося - можливі затримки від антивіруса");

        Directory.CreateDirectory(tool);
        Native.Hide(tool);
        Ui.Note("розпаковую лише те, що потрібно обраному режиму:");
        string err; int nfiles; long nbytes;
        DateTime unpackT0 = DateTime.Now;
        bool unpacked = Payload.Extract(tool, c.Full, out err, out nfiles, out nbytes);
        Eta.Done("unpack", DateTime.Now - unpackT0, unpacked);
        if (!unpacked)
        {
            Ui.Line("  [X] " + err, Ui.Sev.Bad);
            Cleanup(tool, workRoot);
            Ui.Pause("Enter для виходу...");
            return 1;
        }

        string ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string work = Path.Combine(workRoot, c.Case + "_" + ts);
        string inDir = Path.Combine(work, "input");
        string outDir = Path.Combine(work, "output");
        Directory.CreateDirectory(inDir);
        Directory.CreateDirectory(outDir);
        string log = Path.Combine(work, "_collector.log");
        _log = log;

        string kape = Path.Combine(tool, "kape.exe");
        string sevenZa = Path.Combine(tool, @"7za\7za.exe");
        if (!File.Exists(kape))
        {
            Ui.Line("  [X] kape.exe не розпакувався.", Ui.Sev.Bad);
            Cleanup(tool, workRoot);
            Ui.Pause("Enter для виходу...");
            return 1;
        }

        // ---- targets ---------------------------------------------------------------
        List<string> targets = new List<string>();
        targets.Add(c.Full ? "DFIRbot_Full" : "DFIRbot_Fast");

        if (c.Comms == "2")
        {
            long gb;
            string biggest;
            string verdict = CommsSize(c.Drive, out gb, out biggest);
            Ui.Note("обсяг пошти й месенджерів: " + gb + " ГБ" +
                    (biggest.Length > 0 ? "   найбільше: " + biggest : ""));
            if (verdict == "HUGE")
            {
                Gap("пошта і месенджери", gb + " ГБ - завеликий обсяг, збір вимкнено");
                c.Comms = "1";
            }
            else
            {
                if (verdict == "BIG") Ui.Line("      [!] Це багато - збір триватиме довше.", Ui.Sev.Warn);
                targets.Add("DFIRbot_Comms");
            }
        }

        if (c.WantMemFiles)
        {
            string why;
            if (MemSpaceOk(workRoot, env.RamBytes, out why)) targets.Add("MemoryFiles");
            else { Gap("файли пам'яті", why); c.Memory = "1"; }
        }

        Console.WriteLine();
        Ui.Section("ЗБІР   //   " + c.ModeLabel + "   диск " + c.Drive + ":   справа " + c.Case);

        int rc = Runner.Run(kape,
            "--tsource " + c.Drive + ": --tdest \"" + inDir + "\" --tflush --ifw true --target "
            + string.Join(",", targets.ToArray()),
            tool, log, "1/4", "Збір артефактів з " + c.Drive + ":", 0);
        if (rc != 0) Gap("збір артефактів", "kape.exe повернув код " + rc);

        // Pull the page/hibernation files OUT of the raw tree before anything else touches
        // it. Left in place they would be packed into input.zip, making that archive as big
        // as the machine's RAM - the exact problem the separate memory archive exists to fix.
        string memDir = Path.Combine(work, "memory");
        int memMoved = 0;
        long memBytes = 0;
        if (c.WantMemFiles) Guard("файли пам'яті (винесення)", delegate ()
        {
            Directory.CreateDirectory(memDir);
            foreach (string f in SafeFiles(inDir))
            {
                string n = Path.GetFileName(f).ToLowerInvariant();
                if (n != "pagefile.sys" && n != "swapfile.sys" && n != "hiberfil.sys") continue;
                long sz = Lp.Size(f);
                if (sz < 0) continue;
                if (Lp.Move(f, Path.Combine(memDir, Path.GetFileName(f))))
                {
                    memMoved++;
                    memBytes += sz;
                }
            }
            if (memMoved > 0)
                Ui.Note("файли пам'яті винесено в окремий архів: " + memMoved
                        + " шт, " + Ui.Gb(memBytes) + " ГБ");
        });

        // ---- modules ---------------------------------------------------------------
        string mods = c.Quiet ? QUIET_MODS : (c.Full ? FULL_MODS : FAST_MODS);
        rc = Runner.Run(kape,
            "--msource \"" + inDir + "\" --mdest \"" + outDir + "\" --mflush --module " + mods,
            tool, log, "2/4", "Розбір зібраного", 0);
        if (rc != 0) Gap("розбір артефактів", "kape.exe повернув код " + rc);
        // A module that silently produced nothing used to be invisible: KAPE exits 0 whether
        // PECmd wrote a CSV or not. Check the families the bot actually reads, and for the two
        // execution artefacts that went missing on the first v4.4 case (ShimCache, Prefetch)
        // run the parser directly when KAPE's module pass left nothing behind.
        Guard("перевірка виходу модулів", delegate () { RescueExecArtefacts(tool, outDir, inDir); CheckModuleOutput(outDir, inDir); });

        // ---- our own analysis (AFTER the modules: --mflush wipes outDir) -------------
        Console.WriteLine();
        Ui.Line("   Власний аналіз:", Ui.Sev.Plain);

        Crypto.WriteCsv(enc, Path.Combine(outDir, c.Live ? @"live\encryption_status.csv"
                                                         : "encryption_status_examiner.csv"));
        env.WriteCsv(Path.Combine(outDir, "environment_restrictions.csv"));
        // Prefetch: the one execution artefact with a REAL run time. On the first v4.4 case the
        // archive had no Prefetch at all and nobody could tell whether the machine had it
        // switched off or the collector had lost it. Recorded either way - AFTER WriteCsv,
        // which rewrites the file (the first v4.5 build appended the row too early and lost it).
        if (c.Live) Guard("стан Prefetch", delegate () { PrefetchStatus(inDir, outDir, c.Drive); });

        SelfDeclaration(outDir, workRoot, tool);

        if (c.Live)
        {
            Defender.WriteEvidence(Path.Combine(outDir, @"live\defender_exclusions.csv"));
            Ui.Note("винятки Defender цієї машини записано як доказ");
            Autoruns(tool, outDir, c);
        }

        // ---- ALL PowerShell in ONE process --------------------------------------
        // Six separate scripts meant six powershell.exe launches and six distinct script
        // texts in the examined machine's EID 4104 log. vao_collect_all.ps1 runs the same
        // six bodies in one process, so we leave one footprint instead of six.
        string treeFile = Path.Combine(outDir, "filesystem_tree.txt");
        string suspFile = Path.Combine(outDir, "suspicious_files.txt");
        string hashFile = Path.Combine(outDir, "hashes.csv");
        string encFile  = Path.Combine(outDir, "encrypted_files.csv");
        string motwDir  = Path.Combine(outDir, "motw");

        PsStep(tool, "vao_collect_all.ps1", new Dictionary<string, string> {
                   { "CsvDir", outDir }, { "OutDir", outDir }, { "Drive", c.Drive },
                   { "Live", c.Live ? "1" : "0" },
                   { "Fast", c.Full ? "0" : "1" } },
               "збір PowerShell-кроків (дерево, підозрілі, хеші, шифроване, MOTW, жива система)",
               60 * 60 * 1000,
               new string[] { "DIRS", "FILES", "TOTAL", "HASHED", "CONT", "PROC", "CONN" },
               treeFile);

        // each step still declares its own gap when its file did not appear. In FAST the two
        // disk sweeps are OFF BY DESIGN (v4.4) - say so, instead of "file not created", which
        // read as a failure on every FAST run.
        if (!File.Exists(suspFile)) Gap("підозрілі файли за MFT", "файл не створено");
        if (!File.Exists(hashFile)) Gap("хешування підозрілих файлів", c.Full ? "файл не створено" : "режим FAST: крок вимкнено навмисно (є у FULL)");
        if (!File.Exists(encFile))  Gap("пошук шифрованих файлів", c.Full ? "файл не створено" : "режим FAST: крок вимкнено навмисно (є у FULL)");
        if (!Directory.Exists(motwDir)) Gap("джерела завантажень (MOTW)", "теку не створено");

        // Alternate data streams: names come from $MFT already, the CONTENT only from here.
        // Target-disk step -> both scenarios. Ads.cs explains the 23.10 notary cases.
        Guard("потоки ADS", delegate ()
        {
            Ui.Note("-> приховані потоки ADS (вміст до 1 МБ)...");
            Ads.Result ar = Ads.Scan(c.Drive, outDir, c.Full, Gap);
            Ui.Note("   потоків: " + ar.Seen + "   стандартних: " + ar.Benign
                    + "   нестандартних: " + ar.Rows + "   вміст збережено: " + ar.Saved);
        });

        string execCsv = Path.Combine(outDir, "execution_findings.csv");
        VaoStep(tool, "execscan --csvdir \"" + outDir + "\" --txt \""
                    + Path.Combine(outDir, "execution_findings.txt") + "\" --csv \"" + execCsv + "\"",
                "аналіз слідів запуску", new string[] { "TOTAL", "HOSTS" }, execCsv, "exec");

        if (c.Live)
            VaoStep(tool, "screenshot --outdir \"" + outDir + "\"", "знімок робочого столу",
                    new string[] { "SHOTS" }, null);

        // ---- raw evidence into the OUTPUT archive ------------------------------------
        string raw = Path.Combine(outDir, "_raw");
        Ui.Note("сирі докази (кущі реєстру, бази браузерів, RDP-кеш)...");
        DateTime rawT0 = DateTime.Now;
        Guard("кущі реєстру (сирі)", delegate () { CopyRegistryHives(inDir, raw); });
        Guard("браузерні бази (сирі)", delegate ()
        {
            int br = CopyBrowserRaw(inDir, Path.Combine(raw, "browsers"));
            Ui.Note("  бази браузерів: " + br + " файлів");
            // Zero browser databases used to be silent. Two notary phishing cases were parsed
            // with an empty SQLDatabases folder and nobody noticed until the delivery point was
            // already lost, so an empty result is now a recorded gap, not a quiet zero.
            if (br == 0)
                Gap("браузерні бази", "у зібраному KAPE-вході немає History/places.sqlite - "
                                    + "перевір ціль WebBrowsers і чи не заблоковані профілі");
        });
        Guard("RDP-кеш (сирий)", delegate () { CopyRdpCache(inDir, Path.Combine(raw, "rdpcache")); });
        if (c.WantMemFiles) Guard("мінідампи", delegate () { RouteDumps(inDir, Path.Combine(raw, "minidump"), memDir); });
        if (c.Comms == "2") Guard("пошта і месенджери (копія)", delegate () { CopyComms(inDir, Path.Combine(raw, "comms")); });
        Eta.Done("raw", DateTime.Now - rawT0, true);

        // ---- live-only state ---------------------------------------------------------
        if (c.Live)
        {
            DateTime netT0 = DateTime.Now;
            Guard("мережевий знімок", delegate () { NetworkSnapshot(Path.Combine(outDir, @"live\network")); });
            Eta.Done("net", DateTime.Now - netT0, true);

            // The live snapshot is NOT launched here any more: vao_collect_all.ps1 already ran
            // Invoke-VaoLiveResponse into this exact directory when Live=1. Calling it again
            // meant a second powershell.exe and a second EID 4104 record for work that was
            // already done - the opposite of why the scripts were merged. Only the gap check
            // stays, in the same shape as the other steps.
            string liveSys = Path.Combine(outDir, @"live\system");
            if (!Directory.Exists(liveSys))
                Gap("живий зріз системи (процеси, з'єднання, канали)", "теку не створено");
        }

        // Memory last among the collection steps, deliberately: if a capture ever does
        // bugcheck the machine, the triage is already on disk. That is also what the
        // encryption panel tells the operator ("спершу тріаж, потім захоплення RAM"), and the
        // screen and the code must not disagree.
        string ramDump = null;
        if (c.WantRamDump)
            Guard("дамп оперативної пам'яті", delegate ()
            { ramDump = Memory.CaptureFull(tool, c.RamDest, c.Case, outDir, env.RamBytes, Gap); });
        else if (c.WantProcDumps)
            Guard("дампи процесів", delegate ()
            {
                Ui.Note("-> дампи окремих процесів (без драйвера)...");
                Memory.CaptureProcesses(outDir, Gap);
            });

        string fpCsv = Path.Combine(outDir, "_collector_footprint.csv");
        DateTime fpT0 = DateTime.Now;
        Guard("опис власного сліду", delegate ()
        {
            VaoStep(tool, "footprint --outdir \"" + outDir + "\" --selfdir \"" + tool
                        + "\" --workroot \"" + workRoot + "\" --start \"" + ts
                        + "\" --version \"" + Ui.VER + "\"",
                    "опис власного сліду в системі", new string[] { "PF", "TMP" }, fpCsv);
        });
        Eta.Done("footprint", DateTime.Now - fpT0, true);

        // what our own file operations could not reach - one honest row, not a red crash
        string lpGap = Lp.GapText();
        if (lpGap.Length > 0) Gap("довгі шляхи", lpGap);
        WriteGaps(Path.Combine(outDir, "collection_gaps.csv"));

        // ---- packing -------------------------------------------------------------------
        Console.WriteLine();
        Guard("чистка слідів інструментів", delegate () { StripToolTraces(outDir); StripToolTraces(inDir); });
        string zipIn = Path.Combine(work, c.Case + "_input.zip");
        string zipOut = Path.Combine(work, c.Case + "_output.zip");

        string zipMem = null;
        if (File.Exists(sevenZa))
        {
            // -mx=1 for the raw tree: it is gigabytes of already-compressed evidence (evtx,
            // sqlite, hives), and level 5 spent minutes shaving a few percent off a file the
            // operator carries on a disk anyway. The parsed archive stays at 5 - it is the one
            // that travels over the tunnel to the bot.
            // Every archive is packed ONCE, already encrypted: -mem=AES256 with a random
            // password per archive. Names stay visible so the archive opens like an archive
            // and it is obvious what was collected; the contents need the password. No plain
            // archive is ever written, and no second copy of the data is needed.
            string pwIn = Seal.NewPassword(), pwOut = Seal.NewPassword();
            PackEncrypted(inDir, zipIn, pwIn, "3/4", "Пакування сирих даних");
            AttachKey(zipIn, pwIn, sevenZa, log, "архів сирих даних", ref _sealIn);
            // timing written before the output zip so it is inside it
            Eta.WriteCsv(Path.Combine(outDir, "_collector_timing.csv"));
            PackEncrypted(outDir, zipOut, pwOut, "4/4", "Пакування розпарсеного");
            AttachKey(zipOut, pwOut, sevenZa, log, "архів для бота", ref _sealOut);
            Guard("архів пам'яті", delegate () { zipMem = PackMemory(sevenZa, c, work, memDir, ramDump, log); });
        }
        else Gap("пакування", "7za.exe не розпакувався");

        // ---- finish ----------------------------------------------------------------------
        if (File.Exists(zipOut))
        {
            try { Directory.Delete(inDir, true); } catch { }
            try { Directory.Delete(outDir, true); } catch { }
        }

        Console.WriteLine();
        Console.WriteLine("  " + new string('=', 60));
        if (File.Exists(zipOut))
        {
            Ui.Line("   ГОТОВО.", Ui.Sev.Good);
            Console.WriteLine("     [для бота]    " + zipOut + Sz(zipOut));
            if (zipMem != null && File.Exists(zipMem))
            {
                Console.WriteLine("     [пам'ять]     " + zipMem + Sz(zipMem));
                Console.WriteLine("                   -> кнопка \"RAM Memory\" в боті, окремо від основного");
                long mb = new FileInfo(zipMem).Length;
                if (mb > UPLOAD_LIMIT)
                    Ui.Line("     [!] Це більше за ліміт завантаження в бота ("
                            + Ui.Gb(UPLOAD_LIMIT) + " ГБ) - несіть носій фізично"
                            + " або зберіть лише файли пам'яті.", Ui.Sev.Warn);
            }
            if (File.Exists(zipIn)) Console.WriteLine("     [сирі дані]   " + zipIn + Sz(zipIn));
            SealReport(zipIn, zipMem);
        }
        else Ui.Line("   [X] Архів не створено. Перевірте " + outDir, Ui.Sev.Bad);
        if (File.Exists(zipOut))
        {
            Ui.Line("   [!] Виняток Defender на " + workRoot + " ЛИШЕНО навмисно,", Ui.Sev.Warn);
            Ui.Note("       щоб антивірус не видалив архів із доказами. Зніміть його");
            Ui.Note("       після того, як скопіюєте архіви. Обидва наші шляхи перелічені");
            Ui.Note("       у _collector_self.txt, щоб їх не сплутали зі слідами зловмисника.");
        }
        else DropWorkExclusion(workRoot);
        if (_gaps.Count > 0)
            Ui.Line("   [!] Кроків пропущено: " + _gaps.Count + " (перелік у collection_gaps.csv)",
                    Ui.Sev.Warn);
        Console.WriteLine("  " + new string('=', 60));

        Cleanup(tool, null);
        try
        {
            if (File.Exists(zipOut) && !Ui.Unattended)
                System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + zipOut + "\"");
        }
        catch { }
        Ui.Pause("Enter, щоб закрити...");
        return 0;
    }

    // =============================== helpers ==========================================

    /// <summary>
    /// Give back the toolkit exclusion (its folder is about to vanish), but KEEP the one on
    /// the work root while the archives are still sitting there: on a machine hit by a
    /// ransomware the input archive legitimately contains the malware, and Defender would
    /// quarantine our evidence. The operator is told to remove it after copying the archives,
    /// and both paths are declared in _collector_self.txt so nobody reads them as tampering.
    /// </summary>
    /// <summary>The bot's uploader ceiling. Anything above this cannot be sent the usual way.</summary>
    const long UPLOAD_LIMIT = 32L * 1073741824L;

    /// <summary>Which archives carry a recoverable password - for an honest closing report.</summary>
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
    }

    /// <summary>
    /// Put the wrapped password and the README into a finished archive. If this fails the
    /// archive still exists and is still encrypted - but NOBODY could ever open it, so that
    /// is reported loudly rather than as a footnote.
    /// </summary>
    static void AttachKey(string archive, string password, string sevenZa, string log,
                          string label, ref bool flag)
    {
        if (!File.Exists(archive)) return;
        string err = Seal.Attach(sevenZa, archive, password, log);
        if (err == null) { flag = true; return; }
        Gap("ключ до архіву: " + label, err);
        Ui.Line("   [X] " + label + ": пароль НЕ вкладено в архів (" + err + ").", Ui.Sev.Bad);
        Ui.Note("       Архів зашифрований, але відкрити його не зможе ніхто.");
        Ui.Note("       Запишіть цей пароль зараз, іншого шансу не буде:");
        Ui.Line("       " + password, Ui.Sev.Warn);
    }

    /// <summary>
    /// Say plainly what is protected and how to look inside. An operator who believes an
    /// archive is open when it is not (or the reverse) is the failure this prevents.
    /// </summary>
    static void SealReport(string zipIn, string zipMem)
    {
        System.Collections.Generic.List<string> bad = new System.Collections.Generic.List<string>();
        if (!_sealOut) bad.Add("для бота");
        if (File.Exists(zipIn) && !_sealIn) bad.Add("сирі дані");
        if (zipMem != null && File.Exists(zipMem) && !_sealMem) bad.Add("пам'ять");

        if (_sealOut || _sealIn || _sealMem)
        {
            Ui.Line("   [під паролем] список файлів видно, самі файли - ні.", Ui.Sev.Good);
            Ui.Note("       Боту пароль вводити не треба - він усередині архіву,");
            Ui.Note("       зашифрований на наш сервер (ключ " + SealKey.KeyId + ").");
            Ui.Note("       Подивитись самому: show_password.cmd <архів> на нашому хості.");
        }
        if (bad.Count > 0)
            Ui.Line("   [!] Без вкладеного пароля: " + string.Join(", ", bad.ToArray())
                    + " - причина в collection_gaps.csv.", Ui.Sev.Warn);
    }

    static string Sz(string path)
    {
        try { return "   (" + Ui.Gb(new FileInfo(path).Length) + " ГБ)"; }
        catch { return ""; }
    }

    /// <summary>
    /// Pack the memory artefacts into their own archive. Compression is chosen by size, per
    /// the owner's decision: a small image is worth compressing (it then fits the uploader),
    /// a large one is stored as-is because an hour of zipping on the victim's machine buys
    /// nothing we can use - the result would be over the upload ceiling either way.
    /// The archive is built NEXT TO THE DUMP so a 128 GB file is never copied across disks.
    /// </summary>
    static string PackMemory(string sevenZa, Config c, string work, string memDir,
                             string ramDump, string log)
    {
        bool haveFiles = Directory.Exists(memDir) && Directory.GetFiles(memDir).Length > 0;
        bool haveDump = ramDump != null && File.Exists(ramDump);
        if (!haveFiles && !haveDump) return null;

        long total = 0;
        if (haveDump) { try { total += new FileInfo(ramDump).Length; } catch { } }
        if (haveFiles)
            foreach (string f in Directory.GetFiles(memDir))
                try { total += new FileInfo(f).Length; } catch { }

        // Under 16 GB: compress, it may then fit the uploader. Above: store, and say why.
        bool compress = total <= 16L * 1073741824L;
        string dir = haveDump ? Path.GetDirectoryName(ramDump) : work;
        string zip = Path.Combine(dir, c.Case + "_memory.zip");

        Ui.Note(compress
            ? "пакую пам'ять зі стисненням (" + Ui.Gb(total) + " ГБ)"
            : "пам'ять " + Ui.Gb(total) + " ГБ - пакую БЕЗ стиснення, щоб не чекати годину");

        string pw = Seal.NewPassword();
        // Дамп і файли памʼяті - в ОДИН прохід: наш архіватор пише архів цілком, а не
        // дописує до наявного. Дамп додається окремим файлом поруч із деревом memDir.
        string extra = (haveDump && File.Exists(ramDump)) ? ramDump : null;
        string zerr = null;
        Ui.ProgressStart("5/5", "Пакування пам'яті", TimeSpan.Zero);
        DateTime zt0 = DateTime.Now;
        zerr = ZipAes.Create(zip, haveFiles ? memDir : Path.GetDirectoryName(ramDump), pw,
                             extra, null);
        Ui.ProgressDone("5/5", "Пакування пам'яті", DateTime.Now - zt0, zerr == null);

        if (zerr != null || !File.Exists(zip)) { Gap("архів пам'яті", zerr ?? "архів не створено"); return null; }
        AttachKey(zip, pw, sevenZa, log, "архів пам'яті", ref _sealMem);

        // The image is inside the archive now; keeping the loose copy would double the space.
        if (haveDump) { try { File.Delete(ramDump); } catch { } }
        try { if (Directory.Exists(memDir)) Directory.Delete(memDir, true); } catch { }
        return zip;
    }

    static void Cleanup(string tool, string workRoot)
    {
        try { Defender.Remove(tool); } catch { }
        Payload.KillDir(tool);
    }

    /// <summary>Called only when there is nothing left to protect.</summary>
    static void DropWorkExclusion(string workRoot)
    {
        try { Defender.Remove(workRoot); } catch { }
    }

    /// <summary>
    /// Remove OUR OWN extracted-toolkit folders left in %TEMP% by a run that was interrupted.
    /// Found on this host after two aborted tests: 376 MB each, sitting on the machine we are
    /// supposed to be disturbing as little as possible.
    ///
    /// Only ours (DFIRTriage_* / DFIRCollector_*), and only if untouched for two hours, so a
    /// second collector running in parallel cannot have its toolkit deleted underneath it.
    /// </summary>
    static int PurgeOwnStaleDirs()
    {
        int n = 0;
        try
        {
            string temp = Path.GetTempPath();
            foreach (string d in Directory.GetDirectories(temp))
            {
                string leaf = Path.GetFileName(d);
                if (!(leaf.StartsWith("DFIRTriage_", StringComparison.OrdinalIgnoreCase)
                   || leaf.StartsWith("DFIRCollector_", StringComparison.OrdinalIgnoreCase)))
                    continue;
                DateTime newest = Directory.GetLastWriteTimeUtc(d);
                try
                {
                    foreach (string f in Directory.GetFiles(d, "*", SearchOption.TopDirectoryOnly))
                    {
                        DateTime t = File.GetLastWriteTimeUtc(f);
                        if (t > newest) newest = t;
                    }
                }
                catch { }
                if ((DateTime.UtcNow - newest).TotalHours < 2) continue;
                Payload.KillDir(d);
                if (!Directory.Exists(d)) n++;
            }

            // The PowerShell capability probe in Env writes dfp_XXXXXXXX.ps1 into %TEMP% and
            // deletes it in a finally block - unless the process is killed mid-probe. What is
            // left then is a stray .ps1 in a temp folder, which is exactly the shape our own
            // detection rules treat as suspicious: on a second run against the same machine we
            // would be flagging our own leftovers. Same two-hour rule as above.
            foreach (string f in Directory.GetFiles(temp, "dfp_*.ps1"))
            {
                try
                {
                    if ((DateTime.UtcNow - File.GetLastWriteTimeUtc(f)).TotalHours < 2) continue;
                    File.Delete(f);
                    n++;
                }
                catch { }
            }
        }
        catch { }
        return n;
    }

    /// <summary>
    /// Did the step actually leave something behind? The 2026-08-13 test run finished with
    /// exit 0 and an archive that looked complete, while four analysis steps had written
    /// nothing at all - they reported counts and no file. A step is only done when its output
    /// exists, so check for it rather than trusting the exit path.
    /// </summary>
    static bool Produced(string path)
    {
        if (path == null) return true;                       // step has no single output file
        try
        {
            if (Directory.Exists(path)) return Directory.GetFiles(path).Length > 0;
            FileInfo fi = new FileInfo(path);
            return fi.Exists && fi.Length > 8;               // header-only CSV is not a result
        }
        catch { return false; }
    }

    /// <summary>Run one of the not-yet-ported PowerShell helpers through the stdin bridge.</summary>
    static Dictionary<string, string> PsStep(string tool, string script,
        Dictionary<string, string> args, string label, int timeoutMs, string[] show,
        string expect)
    {
        string path = Path.Combine(tool, @"Modules\!DFIRbot\" + script);
        if (!Ps.Available) { Gap(label, "PowerShell недоступний на цій машині"); return null; }
        if (!File.Exists(path)) { Gap(label, "сценарій не розпакувався"); return null; }

        // "ps" phase: start line, heartbeat every 30 s with the helper's VAO_STEP marker,
        // done line - this pass used to be a silent minute-long gap on the screen
        string[] lines = Ps.Run(path, args, timeoutMs, "ps", label, _log);
        if (lines == null) { Gap(label, "не вдалося запустити"); return null; }
        Dictionary<string, string> kv = Ps.Kv(lines);
        if (show != null)
        {
            List<string> parts = new List<string>();
            foreach (string k in show) if (kv.ContainsKey(k)) parts.Add(k + "=" + kv[k]);
            if (parts.Count > 0) Ui.Note("   " + string.Join("   ", parts.ToArray()));
        }
        if (!Produced(expect)) Gap(label, "крок не створив " + Path.GetFileName(expect));
        return kv;
    }

    /// <summary>Run one of our own native tools (vao_triage) - unaffected by any script policy.</summary>
    static Dictionary<string, string> VaoStep(string tool, string args, string label,
                                              string[] show, string expect)
    {
        return VaoStep(tool, args, label, show, expect, null);
    }

    /// <summary>With a phase the step reports progress like the external tools do.</summary>
    static Dictionary<string, string> VaoStep(string tool, string args, string label,
                                              string[] show, string expect, string phase)
    {
        string exe = Path.Combine(tool, @"Modules\bin\vao_triage.exe");
        if (phase == null) Ui.Note("-> " + label + "...");
        if (!File.Exists(exe)) { Gap(label, "vao_triage.exe не розпакувався"); return null; }
        string[] lines;
        if (phase != null)
        {
            bool ok;
            lines = Runner.RunCapture(exe, args, tool, _log, phase, label, 30 * 60 * 1000, null, 0, out ok);
        }
        else lines = Runner.Capture(exe, args, tool, 30 * 60 * 1000);
        if (lines == null) { Gap(label, "інструмент не запустився"); return null; }
        if (!Produced(expect)) Gap(label, "крок не створив " + Path.GetFileName(expect));
        Dictionary<string, string> kv = Ps.Kv(lines);
        if (show != null)
        {
            List<string> parts = new List<string>();
            foreach (string k in show) if (kv.ContainsKey(k) && kv[k].Length > 0) parts.Add(k + "=" + kv[k]);
            if (parts.Count > 0) Ui.Note("   " + string.Join("   ", parts.ToArray()));
        }
        return kv;
    }

    /// <summary>
    /// Autoruns without the PowerShell wrapper module. autorunsc is an ordinary executable,
    /// so it runs where powershell.exe would not.
    /// </summary>
    static void Autoruns(string tool, string outDir, Config c)
    {
        if (!c.Full) return;                       // signature checks are slow; FULL only
        string exe = Path.Combine(tool, @"Modules\bin\autorunsc64.exe");
        if (!File.Exists(exe)) exe = Path.Combine(tool, @"Modules\bin\autorunsc.exe");
        if (!File.Exists(exe)) { Gap("Autoruns", "autorunsc не розпакувався"); return; }
        string dir = Path.Combine(outDir, "Autoruns");
        Directory.CreateDirectory(dir);
        Ui.Note("-> персистентність (Autoruns)...");
        string[] lines = Runner.Capture(exe, "-accepteula -a * -s -c -h *", tool, 15 * 60 * 1000);
        if (lines == null || lines.Length < 2) { Gap("Autoruns", "інструмент не повернув даних"); return; }
        try
        {
            File.WriteAllText(Path.Combine(dir, "Autoruns.csv"),
                              string.Join("\r\n", lines), new UTF8Encoding(false));
            Ui.Note("   записів: " + (lines.Length - 1));
        }
        catch (Exception ex) { Gap("Autoruns", ex.Message); }
    }

    /// <summary>
    /// Network state from ordinary executables only - no PowerShell. ipconfig/arp/netsh are
    /// EXEs, so a script policy cannot block them.
    /// </summary>
    static void NetworkSnapshot(string dir)
    {
        Ui.Note("-> мережевий знімок (DNS / з'єднання / firewall)...");
        try { Directory.CreateDirectory(dir); } catch { return; }
        string sys = Environment.GetFolderPath(Environment.SpecialFolder.System);

        // Same file names and columns the bot already ingests (live/*.csv -> fb_live_network).
        int conns = Net.WriteConnectionsCsv(Path.Combine(dir, "netstat.csv"), Net.ProcessNames());
        Ui.Note("   з'єднань: " + conns);
        if (!Net.WriteDnsCache(Path.Combine(dir, "dns_cache.csv"), Path.Combine(dir, "dns_cache.txt")))
            Gap("кеш DNS у CSV", "PowerShell недоступний - збережено текстом");

        Dump(Path.Combine(sys, "ipconfig.exe"), "/all", Path.Combine(dir, "ipconfig.txt"));
        Dump(Path.Combine(sys, "arp.exe"), "-a", Path.Combine(dir, "arp.txt"));
        Dump(Path.Combine(sys, "netsh.exe"), "advfirewall firewall show rule name=all",
             Path.Combine(dir, "firewall_rules.txt"));
        Dump(Path.Combine(sys, "netsh.exe"), "wlan show profiles",
             Path.Combine(dir, "wifi_profiles.txt"));
        try
        {
            File.Copy(Path.Combine(sys, @"drivers\etc\hosts"), Path.Combine(dir, "hosts.txt"), true);
        }
        catch { }
    }

    static void Dump(string exe, string args, string outFile)
    {
        try
        {
            if (!File.Exists(exe)) return;
            string o;
            Env.TryRun(exe, args, null, out o, 120000);
            if (o != null) File.WriteAllText(outFile, o, new UTF8Encoding(false));
        }
        catch { }
    }

    // ---- sizing checks (ported from check_commsize.ps1 / check_memspace.ps1) ---------

    static readonly string[] CommsDirs = {
        @"AppData\Local\Microsoft\Outlook", @"AppData\Roaming\Microsoft\Outlook",
        @"AppData\Roaming\Thunderbird", @"AppData\Roaming\Telegram Desktop",
        @"AppData\Roaming\WhatsApp", @"AppData\Roaming\Signal", @"AppData\Roaming\ViberPC",
        @"AppData\Roaming\Skype", @"AppData\Roaming\discord",
        @"Documents\Outlook Files"
    };

    static string CommsSize(string drive, out long gb, out string biggest)
    {
        long total = 0, max = 0;
        biggest = "";
        try
        {
            string users = drive + @":\Users";
            if (Directory.Exists(users))
                foreach (string u in Directory.GetDirectories(users))
                    foreach (string rel in CommsDirs)
                    {
                        string p = Path.Combine(u, rel);
                        if (!Directory.Exists(p)) continue;
                        long sz = DirSize(p, 3);
                        total += sz;
                        if (sz > max) { max = sz; biggest = Path.GetFileName(u) + @"\" + rel + " " + Ui.Gb(sz) + " ГБ"; }
                    }
        }
        catch { }
        gb = (long)Math.Round(total / 1073741824.0);
        if (total > 60L * 1073741824L) return "HUGE";
        if (total > 10L * 1073741824L) return "BIG";
        return "OK";
    }

    static long DirSize(string dir, int depthLeft)
    {
        long n = 0;
        try
        {
            foreach (string f in Directory.GetFiles(dir))
                try { n += new FileInfo(f).Length; } catch { }
            if (depthLeft > 0)
                foreach (string d in Directory.GetDirectories(dir))
                    n += DirSize(d, depthLeft - 1);
        }
        catch { }
        return n;
    }

    /// <summary>
    /// Filling the target's disk mid-collection destroys evidence, so measure first.
    /// Fail-open on UNKNOWN: a glitch in the check must not silently drop a requested artefact.
    /// </summary>
    static bool MemSpaceOk(string workRoot, long ramBytes, out string why)
    {
        why = "";
        long need = 0;
        try
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                "SELECT AllocatedBaseSize FROM Win32_PageFileUsage"))
                foreach (ManagementObject m in s.Get())
                    need += Convert.ToInt64(m["AllocatedBaseSize"]) * 1048576L;
        }
        catch { }
        if (ramBytes > 0) need += (long)(ramBytes * 0.45);       // hiberfil, if enabled
        if (need == 0) return true;                              // nothing measurable -> proceed
        need = (long)(need * 1.15);
        long free = Drives.FreeOn(workRoot);
        if (free < 0) return true;
        if (free >= need) return true;
        why = "потрібно ~" + Ui.Gb(need) + " ГБ, вільно " + Ui.Gb(free) + " ГБ";
        return false;
    }

    // ---- raw copies -----------------------------------------------------------------

    static void CopyRegistryHives(string inDir, string raw)
    {
        string dst = Path.Combine(raw, "registry");
        Directory.CreateDirectory(dst);
        string[] want = { "SAM", "SYSTEM", "SECURITY", "SOFTWARE", "Amcache.hve" };
        foreach (string f in SafeFiles(inDir))
        {
            string name = Path.GetFileName(f);
            foreach (string w in want)
                if (string.Equals(name, w, StringComparison.OrdinalIgnoreCase))
                    TryCopy(f, Path.Combine(dst, w));
            // Per-user hives keep their owner in the path: the bot attributes RecentDocs,
            // UserAssist, shellbags and RDP targets per user from exactly this layout.
            if (string.Equals(name, "NTUSER.DAT", StringComparison.OrdinalIgnoreCase)
             || string.Equals(name, "UsrClass.dat", StringComparison.OrdinalIgnoreCase))
            {
                string user = UserFromPath(f);
                string ud = Path.Combine(dst, "users", user);
                Directory.CreateDirectory(ud);
                TryCopy(f, Path.Combine(ud, name));
            }
        }
    }

    /// <summary>
    /// Take the LAST "\Users\" in the path, not the first: the working directory itself can
    /// live under C:\Users, which once attributed every hive to the wrong person.
    /// </summary>
    static string UserFromPath(string full)
    {
        try
        {
            string[] parts = full.Split(new string[] { @"\Users\" }, StringSplitOptions.None);
            if (parts.Length > 1)
            {
                string tail = parts[parts.Length - 1];
                int i = tail.IndexOf('\\');
                string u = i > 0 ? tail.Substring(0, i) : tail;
                if (u.Length > 0) return u;
            }
        }
        catch { }
        return "unknown";
    }

    static int CopyBrowserRaw(string inDir, string dst)
    {
        // WAL sidecars must travel with the database or it reads back stale.
        // Added 2026-08-22: KAPE already collects these, the collector simply did not
        // forward them into _raw/browsers, which is the only browser folder the bot
        // reads. Extensions and open tabs answer questions the report asks and had
        // no source at all before.
        string[] names = { "History", "Web Data", "Login Data", "Cookies", "places.sqlite",
                           "formhistory.sqlite", "Shortcuts", "Top Sites", "Favicons",
                           "Preferences", "Secure Preferences", "Bookmarks",
                           "Last Session", "Last Tabs", "Current Session", "Current Tabs",
                           "extensions.json", "cookies.sqlite", "addons.json" };
        int n = 0;
        Directory.CreateDirectory(dst);
        foreach (string f in SafeFiles(inDir))
        {
            string name = Path.GetFileName(f);
            string bare = name;
            foreach (string sfx in new string[] { "-wal", "-shm", "-journal" })
                if (bare.EndsWith(sfx, StringComparison.OrdinalIgnoreCase))
                    bare = bare.Substring(0, bare.Length - sfx.Length);
            bool want = false;
            foreach (string w in names)
                if (string.Equals(bare, w, StringComparison.OrdinalIgnoreCase)) { want = true; break; }
            if (!want) continue;
            string profile = ProfileTag(f);
            // Flat "<profile>__<file>" threw the vendor away: "User Data\Default" is the same
            // string for Chrome and for Edge, so the parsed history could not say WHICH
            // browser fetched the phishing file. The bot's reader already documents
            // _raw/browsers/<user>/<Browser>/<profile>__<file> - write exactly that.
            string sub = Path.Combine(Path.Combine(dst, UserFromPath(f)), BrowserTag(f));
            Directory.CreateDirectory(sub);
            if (TryCopy(f, Path.Combine(sub, profile + "__" + name))) n++;
        }
        return n;
    }

    static string BrowserTag(string full)
    {
        string p = (full ?? "").Replace('/', '\\');
        string[][] map = {
            new string[] { @"\BraveSoftware\",  "Brave"      },
            new string[] { @"\Google\Chrome",   "Chrome"     },
            new string[] { @"\Chromium\",       "Chromium"   },
            new string[] { @"\Microsoft\Edge",  "Edge"       },
            new string[] { @"\Mozilla\Firefox", "Firefox"    },
            new string[] { @"\Opera Software\", "Opera"      },
            new string[] { @"\Yandex",          "Yandex"     },
            new string[] { @"\Vivaldi\",        "Vivaldi"    },
            new string[] { @"\CocCoc\",         "CocCoc"     },
            new string[] { @"\Tor Browser",     "TorBrowser" },
        };
        foreach (string[] m in map)
            if (p.IndexOf(m[0], StringComparison.OrdinalIgnoreCase) >= 0) return m[1];
        return "Other";
    }

    static string ProfileTag(string full)
    {
        try
        {
            string d = Path.GetDirectoryName(full);
            string p1 = Path.GetFileName(d);
            string p2 = Path.GetFileName(Path.GetDirectoryName(d));
            string user = UserFromPath(full);
            string tag = (user + "_" + p2 + "_" + p1).Replace(' ', '_');
            foreach (char bad in Path.GetInvalidFileNameChars()) tag = tag.Replace(bad, '_');
            return tag.Length > 80 ? tag.Substring(tag.Length - 80) : tag;
        }
        catch { return "profile"; }
    }

    static void CopyRdpCache(string inDir, string dst)
    {
        Directory.CreateDirectory(dst);
        foreach (string f in SafeFiles(inDir))
        {
            string name = Path.GetFileName(f);
            bool bmc = name.EndsWith(".bmc", StringComparison.OrdinalIgnoreCase);
            // Win8+ mstsc writes Cache####.bin, not .bmc - matching only .bmc collected
            // nothing on every modern machine until this was found.
            bool bin = name.StartsWith("Cache", StringComparison.OrdinalIgnoreCase)
                       && name.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)
                       && f.IndexOf("Terminal Server Client", StringComparison.OrdinalIgnoreCase) >= 0;
            if (bmc || bin) TryCopy(f, Path.Combine(dst, name));
        }
    }

    /// <summary>
    /// Split .dmp files between the two archives by size. A kernel minidump is a few
    /// hundred KB and names the faulting driver - keep it in the main archive. An
    /// application crash dump is hundreds of MB of process memory: it belongs with the
    /// memory artefacts, not in the archive the investigator uploads first.
    /// </summary>
    const long SMALL_DUMP = 64L * 1048576L;

    static void RouteDumps(string inDir, string smallDst, string memDst)
    {
        int small = 0, big = 0;
        long bigBytes = 0;
        foreach (string f in SafeFiles(inDir))
        {
            if (!f.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase)) continue;
            long sz = Lp.Size(f);
            if (sz < 0) continue;
            if (sz <= SMALL_DUMP)
            {
                if (TryCopy(f, Path.Combine(smallDst, Path.GetFileName(f)))) small++;
            }
            else if (memDst != null)
            {
                if (Lp.Move(f, Path.Combine(memDst, Path.GetFileName(f))))
                {
                    big++;
                    bigBytes += sz;
                }
            }
        }
        if (small > 0) Ui.Note("  мінідампи ядра: " + small);
        if (big > 0)
            Ui.Note("  великих дампів процесів у архів пам'яті: " + big
                    + " (" + Ui.Gb(bigBytes) + " ГБ)");
    }

    static void CopyByExt(string inDir, string dst, string ext)
    {
        Directory.CreateDirectory(dst);
        foreach (string f in SafeFiles(inDir))
            if (f.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                TryCopy(f, Path.Combine(dst, Path.GetFileName(f)));
    }

    static readonly string[] CommsSegs = { "Telegram Desktop", "tdata", "WhatsApp", "Signal",
                                           "Viber", "Skype", "Discord", "Thunderbird", "Outlook" };

    static void CopyComms(string inDir, string dst)
    {
        Directory.CreateDirectory(dst);
        foreach (string f in SafeFiles(inDir))
        {
            bool want = f.EndsWith(".ost", StringComparison.OrdinalIgnoreCase)
                     || f.EndsWith(".pst", StringComparison.OrdinalIgnoreCase);
            if (!want)
            {
                // Whole path SEGMENTS only. Substring matching is the bug that has bitten this
                // project four times ("temp" inside "templates", "7z" inside "7-Zip").
                string[] segs = f.Split('\\');
                foreach (string seg in segs)
                {
                    foreach (string w in CommsSegs)
                        if (string.Equals(seg, w, StringComparison.OrdinalIgnoreCase)) { want = true; break; }
                    if (want) break;
                }
            }
            if (!want) continue;
            string rel = f.StartsWith(inDir, StringComparison.OrdinalIgnoreCase)
                       ? f.Substring(inDir.Length).TrimStart('\\') : Path.GetFileName(f);
            string target = Path.Combine(dst, rel);
            try { Directory.CreateDirectory(Path.GetDirectoryName(target)); } catch { }
            TryCopy(f, target);
        }
    }

    static void StripToolTraces(string dir)
    {
        // The archives must not reveal which toolchain produced them.
        foreach (string f in SafeFiles(dir))
        {
            string n = Path.GetFileName(f).ToLowerInvariant();
            // tool logs and session files are not evidence; the bot listed them as
            // "не розпізнано" (2026-09-05): !SBECmd_Messages.txt, LevelDBDumperOutput.log,
            // ForensicTimeliner *.tle_sess
            if (n.Contains("copylog") || n.Contains("skiplog") || n.Contains("consolelog")
                || (n.Contains("kape") && n.EndsWith(".log"))
                || n == "!sbecmd_messages.txt" || n == "leveldbdumperoutput.log"
                || n.EndsWith(".tle_sess"))
                Lp.Delete(f);
        }
        try
        {
            foreach (string d in Directory.GetDirectories(dir, "!kape", SearchOption.AllDirectories))
                try { Directory.Delete(d, true); } catch { }
        }
        catch { }
    }

    /// <summary>Enumerate files without dying on one unreadable or over-long directory.</summary>
    static IEnumerable<string> SafeFiles(string root)
    {
        foreach (string f in Lp.Walk(root)) yield return Lp.Plain(f);
    }

    static bool TryCopy(string src, string dst)
    {
        return Lp.Copy(src, dst);
    }

    /// <summary>
    /// Is Prefetch on, and did KAPE get the .pf files? Written as rows in
    /// environment_restrictions.csv (check=prefetch) so the bot's coverage block can say
    /// "no Prefetch because the machine has it off" instead of "no Prefetch".
    /// </summary>
    static void PrefetchStatus(string inDir, string outDir, string drive)
    {
        int enable = -1;
        try
        {
            using (Microsoft.Win32.RegistryKey k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"))
            {
                if (k != null) { object v = k.GetValue("EnablePrefetcher"); if (v != null) enable = Convert.ToInt32(v); }
            }
        }
        catch { }
        int onDisk = 0, collected = 0;
        try { onDisk = Directory.GetFiles(drive + @":\Windows\Prefetch", "*.pf").Length; } catch { }
        try
        {
            foreach (string f in SafeFiles(inDir))
                if (f.EndsWith(".pf", StringComparison.OrdinalIgnoreCase)) collected++;
        }
        catch { }
        string state = enable == 0 ? "disabled" : (onDisk == 0 ? "empty" : "enabled");
        string detail = "EnablePrefetcher=" + (enable < 0 ? "?" : enable.ToString())
                      + "; pf_on_disk=" + onDisk + "; pf_collected=" + collected;
        Ui.Note("Prefetch: " + state + " (" + detail + ")");
        try
        {
            File.AppendAllText(Path.Combine(outDir, "environment_restrictions.csv"),
                "prefetch," + state + "," + Env.Csv(detail) + "\r\n", new UTF8Encoding(false));
        }
        catch { }
        if (enable == 0) Gap("Prefetch", "вимкнено на цій машині (EnablePrefetcher=0) - часів запуску з Prefetch не буде");
        else if (onDisk > 0 && collected == 0) Gap("Prefetch", onDisk + " .pf на диску, але KAPE не зібрав жодного");
    }

    /// <summary>
    /// ShimCache and Prefetch straight from the EZ tools when the KAPE module pass produced
    /// nothing for them. On 3-4-19-1N (v4.4) the archive had neither, and the 1024-row
    /// AppCompatCache every v3 case carried was simply gone. Both parsers ship in Modules\bin;
    /// their inputs are in the KAPE input tree; there is no reason to depend on the module
    /// dispatcher alone.
    /// </summary>
    static void RescueExecArtefacts(string tool, string outDir, string inDir)
    {
        string pe = Path.Combine(outDir, "ProgramExecution");
        bool haveShim = false, havePf = false;
        try
        {
            if (Directory.Exists(pe))
                foreach (string f in Directory.GetFiles(pe))
                {
                    string n = Path.GetFileName(f);
                    if (n.IndexOf("AppCompatCache", StringComparison.OrdinalIgnoreCase) >= 0 && new FileInfo(f).Length > 8) haveShim = true;
                    if (n.IndexOf("PECmd_Output", StringComparison.OrdinalIgnoreCase) >= 0 && new FileInfo(f).Length > 8) havePf = true;
                }
        }
        catch { }
        if (haveShim && havePf) return;

        string systemHive = null, pfDir = null;
        foreach (string f in SafeFiles(inDir))
        {
            string n = Path.GetFileName(f);
            if (systemHive == null && string.Equals(n, "SYSTEM", StringComparison.OrdinalIgnoreCase)
                && f.IndexOf(@"\config\", StringComparison.OrdinalIgnoreCase) >= 0) systemHive = f;
            if (pfDir == null && n.EndsWith(".pf", StringComparison.OrdinalIgnoreCase)) pfDir = Path.GetDirectoryName(f);
            if (systemHive != null && pfDir != null) break;
        }
        Directory.CreateDirectory(pe);
        if (!haveShim && systemHive != null)
        {
            string exe = Path.Combine(tool, @"Modules\bin\AppCompatCacheParser.exe");
            if (File.Exists(exe))
            {
                Ui.Note("-> ShimCache напряму (модуль KAPE нічого не дав)...");
                string[] o = Runner.Capture(exe, "-f \"" + systemHive + "\" --csv \"" + pe + "\" --csvf rescued_SYSTEM_AppCompatCache.csv",
                               tool, 10 * 60 * 1000);
                NoteToolFailure("ShimCache (AppCompatCacheParser)", pe, "AppCompatCache", o);
            }
        }
        if (!havePf && pfDir != null)
        {
            string exe = Path.Combine(tool, @"Modules\bin\PECmd.exe");
            if (File.Exists(exe))
            {
                Ui.Note("-> Prefetch напряму (модуль KAPE нічого не дав)...");
                string[] o = Runner.Capture(exe, "-d \"" + pfDir + "\" --csv \"" + pe + "\" --csvf rescued_PECmd_Output.csv --mp -q",
                               tool, 10 * 60 * 1000);
                NoteToolFailure("Prefetch (PECmd)", pe, "PECmd_Output", o);
            }
        }
    }

    /// <summary>
    /// The rescue ran and still left no file. The tool said why on its own stdout - keep
    /// that sentence, because "not created" alone sends the analyst hunting the wrong
    /// cause (see case case_08: an unreadable Windows 11 26200 ShimCache format
    /// was read as a stale collector).
    /// </summary>
    static void NoteToolFailure(string what, string outDirPe, string marker, string[] output)
    {
        try
        {
            foreach (string f in Directory.GetFiles(outDirPe))
                if (Path.GetFileName(f).IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0
                    && new FileInfo(f).Length > 8) return;   // it worked after all
        }
        catch { }
        string why = "";
        if (output != null)
            foreach (string line in output)
            {
                string t = (line ?? "").Trim();
                if (t.Length == 0) continue;
                if (t.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0
                    || t.IndexOf("Unknown version", StringComparison.OrdinalIgnoreCase) >= 0
                    || t.IndexOf("Exception", StringComparison.OrdinalIgnoreCase) >= 0
                    || t.IndexOf("Processed 0 out of", StringComparison.OrdinalIgnoreCase) >= 0)
                { why = t; break; }
            }
        if (why.Length > 300) why = why.Substring(0, 300);
        Gap("парсер " + what, why.Length > 0
            ? ("вхідні файли є, парсер запущено, але він не впорався: " + why)
            : "вхідні файли є, парсер запущено, файл не створено (причина невідома)");
    }

    /// <summary>
    /// The module families the bot reads, and the file each leaves behind. KAPE exits 0
    /// whether or not a module wrote anything, so absence has to be checked here. Only what
    /// has an input is demanded: no .pf collected means no PECmd output is expected.
    /// </summary>
    static void CheckModuleOutput(string outDir, string inDir)
    {
        bool anyPf = false, anySystem = false, anyEvtx = false, anyMft = false, anyAmcache = false;
        foreach (string f in SafeFiles(inDir))
        {
            string n = Path.GetFileName(f);
            if (n.EndsWith(".pf", StringComparison.OrdinalIgnoreCase)) anyPf = true;
            else if (string.Equals(n, "SYSTEM", StringComparison.OrdinalIgnoreCase)) anySystem = true;
            else if (n.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase)) anyEvtx = true;
            else if (string.Equals(n, "$MFT", StringComparison.OrdinalIgnoreCase)) anyMft = true;
            else if (string.Equals(n, "Amcache.hve", StringComparison.OrdinalIgnoreCase)) anyAmcache = true;
        }
        string[][] want = {
            new string[] { "PECmd (Prefetch)",            "ProgramExecution", "PECmd_Output",     anyPf ? "1" : "0" },
            new string[] { "AppCompatCache (ShimCache)",  "ProgramExecution", "AppCompatCache",   anySystem ? "1" : "0" },
            new string[] { "Amcache",                     "ProgramExecution", "Amcache_",         anyAmcache ? "1" : "0" },
            new string[] { "EvtxECmd (журнали)",          "EventLogs",        "EvtxECmd_Output",  anyEvtx ? "1" : "0" },
            new string[] { "MFTECmd ($MFT)",              "FileSystem",       "MFTECmd_$MFT",     anyMft ? "1" : "0" },
        };
        foreach (string[] w in want)
        {
            if (w[3] != "1") continue;
            string dir = Path.Combine(outDir, w[1]);
            bool found = false;
            try
            {
                if (Directory.Exists(dir))
                    foreach (string f in Directory.GetFiles(dir))
                        if (Path.GetFileName(f).IndexOf(w[2], StringComparison.OrdinalIgnoreCase) >= 0
                            && new FileInfo(f).Length > 8) { found = true; break; }
            }
            catch { }
            if (!found) Gap("модуль " + w[0], "вхідні файли є, але " + w[1] + @"\*" + w[2] + "* не створено");
        }
    }

    static DateTime _started = DateTime.Now;

    static void SelfDeclaration(string outDir, string workRoot, string tool)
    {
        try
        {
            // The bot used to infer WHEN we started from the first vao_collector* execution
            // artefact; on a machine with Prefetch off it had nothing to infer from. Say it.
            // Comment lines are ignored by the bot's path reader (analysis/collector_self.py),
            // so the two paths below stay the only things it subtracts.
            File.WriteAllText(Path.Combine(outDir, "_collector_self.txt"),
                "# paths THIS collector added to Defender exclusions (not attacker activity)\r\n"
                + "# collector_version: " + Ui.VER + "\r\n"
                + "# collector_started: " + _started.ToString("yyyy-MM-dd HH:mm:ss") + " (local)\r\n"
                + "# collector_started_utc: " + _started.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + "\r\n"
                + "# collector_host: " + Environment.MachineName + "\r\n"
                + workRoot + "\r\n" + tool + "\r\n", new UTF8Encoding(false));
        }
        catch { }
    }

    static void WriteGaps(string path)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("step,reason");
        foreach (string[] g in _gaps) sb.AppendLine(Env.Csv(g[0]) + "," + Env.Csv(g[1]));
        try { File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false)); } catch { }
    }
}
