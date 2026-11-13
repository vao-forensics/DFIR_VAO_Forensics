#!/usr/bin/env python3
"""Стартовий пакет кураторських DFIR-скілів (глобальні, approved). Авторські стислі процедури
на основі відкритих знань (MITRE ATT&CK, документація Microsoft/Apple/Google). Без ліцензійних текстів."""
import json, os, time

OUT = "/var/lib/docker/volumes/open-webui/_data/skills/skills.json"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

S = [
 ("RDP-доступ і перебір паролів у журналах Windows",
  ["rdp", "4625", "4624", "брутфорс", "перебір", "brute", "logontype", "1149", "віддалений робочий стіл", "remote desktop"],
  "1) Security: 4625 (невдалі входи) — групуй за IpAddress і TargetUserName; серія з одного IP = перебір.\n"
  "2) 4624 з LogonType 10 (RDP) або 3 (мережевий) після серії 4625 = успішний злам — зафіксуй час і обліковий запис.\n"
  "3) TerminalServices-RemoteConnectionManager 1149 і LocalSessionManager 21/24/25 — підтвердження RDP-сесій.\n"
  "4) Перевір джерельний IP (репутація, VPN/хостинг) і що відбувалось одразу після входу (4720/4732/1102)."),
 ("Нові облікові записи й підвищення прав",
  ["4720", "4732", "4728", "4672", "обліковий запис", "адміністратор", "привілеї", "privilege", "account created"],
  "1) 4720 — створення облікового запису; 4722 — увімкнення; 4738 — зміна.\n"
  "2) 4732/4728/4756 — додавання в групи (особливо Administrators/Domain Admins).\n"
  "3) 4672 — вхід зі спецпривілеями. 4) Співстав із часом підозрілого входу; хто ініціатор (SubjectUserName)."),
 ("Очищення журналів (антифорензика)",
  ["1102", "104", "очищення журналу", "очищено", "clear log", "wevtutil", "антифорензика"],
  "1) Security 1102 — журнал аудиту очищено (хто: SubjectUserName). System 104 — очищено інший журнал.\n"
  "2) Шукай wevtutil cl / Clear-EventLog у 4688 (якщо є аудит командного рядка) і PowerShell 4104.\n"
  "3) Очищення одразу після злому — сильний індикатор; відновлюй події з інших джерел (Sysmon, EDR, бекапи .evtx)."),
 ("Закріплення (persistence) у Windows",
  ["persistence", "закріплення", "автозапуск", "run", "runonce", "7045", "4697", "4698", "служба", "задача планувальника", "scheduled task", "wmi"],
  "1) Реєстр: HKCU/HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once); Winlogon Shell/Userinit.\n"
  "2) Служби: System 7045 / Security 4697 — нова служба (шлях до exe поза Program Files/Windows — підозріло).\n"
  "3) Задачі: Security 4698, тека C:\\Windows\\System32\\Tasks (XML: Author, Command, тригер).\n"
  "4) WMI-підписки (EventFilter/Consumer), тека Startup. Для кожного — підпис файлу, час створення, звідки взявся."),
 ("Сліди виконання програм",
  ["prefetch", "amcache", "shimcache", "bam", "userassist", "виконання", "запускалась", "execution", "запуск програми"],
  "1) Prefetch (*.pf): назва, кількість запусків, останні 8 часів запуску (Win10+).\n"
  "2) Amcache.hve: шлях, SHA1 файлу, видавець — перевір SHA1 за репутацією.\n"
  "3) ShimCache (AppCompatCache): факт присутності/запуску, порядок. BAM/DAM: останній запуск по користувачу.\n"
  "4) UserAssist: GUI-запуски користувачем (ROT13). Звір час між джерелами для впевненості."),
 ("PowerShell: виявлення й розкодування",
  ["powershell", "4104", "4103", "-enc", "encodedcommand", "base64", "iex", "downloadstring", "скрипт"],
  "1) Microsoft-Windows-PowerShell/Operational 4104 — текст скриптблоків; 4103 — модульне логування.\n"
  "2) -enc/-EncodedCommand = Base64 від UTF-16LE: розкодуй і шукай IEX, DownloadString, Net.WebClient, Invoke-*.\n"
  "3) Витягни URL/IP/домени як IOC, перевір їх репутацію. 4) Співстав час з мережевими подіями й Prefetch powershell.exe."),
 ("Латеральний рух у мережі",
  ["латеральний", "lateral", "psexec", "psexesvc", "wmi", "winrm", "5145", "4648", "smb", "переміщення"],
  "1) PsExec: служба PSEXESVC (7045), доступ до ADMIN$ (5145), 4624 LogonType 3 на цілі.\n"
  "2) 4648 — вхід з явними обліковими даними (runas/мапування). WinRM: Microsoft-Windows-WinRM 91, wsmprovhost.exe.\n"
  "3) WMI: wmiprvse.exe як батько процесів. Будуй граф: з якої машини → на яку → яким обліковим записом → коли."),
 ("Ексфільтрація даних",
  ["ексфільтрація", "exfil", "rclone", "winscp", "7z", "архів", "вивантаження", "mega", "хмара", "upload"],
  "1) Інструменти: rclone, WinSCP, FileZilla, mega/хмарні клієнти — Prefetch/Amcache/Shim + конфіги (rclone.conf).\n"
  "2) Архівація перед вивантаженням: 7z/rar/zip у Temp/Downloads з великими розмірами.\n"
  "3) Мережа: великі вихідні обсяги, нетипові домени/IP. Встанови що, коли й куди могло піти; оціни обсяг."),
 ("Перевірка підозрілого IP чи домену",
  ["ip", "домен", "domain", "репутація", "vpn", "tor", "хостинг", "ioc", "silent push", "whois", "mullvad"],
  "1) Збагати через Silent Push: ризик, ASN/провайдер, позначки VPN/проксі/Tor, пасивний DNS.\n"
  "2) Не роби висновок лише з памʼяті — дані про IP швидко застарівають.\n"
  "3) Поясни контекст: хостинг/VPN = анонімізація нападника, не обовʼязково його місце. Звʼяжи IP з подіями в справі."),
 ("Форензика браузерів",
  ["браузер", "chrome", "edge", "firefox", "history", "історія", "завантаження", "downloads", "cookies"],
  "1) Chrome/Edge: User Data\\Default\\History (SQLite: urls, visits, downloads), Login Data, Cookies.\n"
  "2) Firefox: places.sqlite (moz_places, moz_historyvisits), downloads — у тій же базі.\n"
  "3) Час у Chrome — мікросекунди від 1601-01-01 (WebKit), у Firefox — мікросекунди Unix. Корелюй з завантаженими файлами."),
 ("Документи: метадані та шкідливий вміст",
  ["документ", "docx", "doc", "xls", "pdf", "метадані", "автор", "макрос", "olevba", "вкладення", "office"],
  "1) Метадані: автор, остання зміна, програма, дати створення/зміни (docProps у DOCX; Info/XMP у PDF).\n"
  "2) Макроси: olevba / oletools — AutoOpen, Shell, URLDownloadToFile, обфускація.\n"
  "3) PDF: /JavaScript, /OpenAction, /Launch, вбудовані файли. 4) Порівняй метадані з версією подій справи."),
 ("Форензика Android",
  ["android", "телефон", "смартфон", "mmssms", "contacts2", "whatsapp", "msgstore", "адб", "adb", "мобільн"],
  "1) Тип копії: логічна (adb backup/агент) vs файлова/фізична — зафіксуй метод і хеш образу.\n"
  "2) Ключові бази: mmssms.db (SMS), contacts2.db, calllog, WhatsApp msgstore.db (+ ключ для .crypt),\n"
  "   Telegram cache4.db, геолокація (Google Location, фото EXIF).\n"
  "3) Часи у мілісекундах Unix. Документуй ланцюг доказів і цілісність (хеші до/після)."),
 ("Форензика iPhone (iOS)",
  ["iphone", "ios", "айфон", "itunes", "бекап", "manifest.db", "sms.db", "knowledgec", "apple"],
  "1) Джерело: зашифрований бекап iTunes/Finder (дає більше даних), Manifest.db — карта файлів.\n"
  "2) sms.db (iMessage/SMS), AddressBook, CallHistory, KnowledgeC.db (активність застосунків), Photos.sqlite.\n"
  "3) Час — Mac Absolute Time (секунди від 2001-01-01). Фіксуй версію iOS і метод отримання."),
 ("Побудова таймлайну інциденту",
  ["таймлайн", "хронологія", "timeline", "послідовність", "коли", "кореляція"],
  "1) Зведи все в UTC; познач часову зону джерела.\n"
  "2) Обʼєднай джерела: журнали подій, файлову систему ($MFT), Prefetch, браузер, мережу.\n"
  "3) Знайди точку входу → закріплення → дії → ексфільтрацію/наслідки. Кожен крок — з посиланням на доказ."),
 ("Статичний аналіз підозрілого файлу",
  ["шкідлив", "malware", "exe", "dll", "хеш", "sha256", "pefile", "yara", "підпис", "вірус"],
  "1) Хеші (MD5/SHA1/SHA256) → репутація.\n"
  "2) PE: секції (ентропія — пакування), імпорти (VirtualAlloc, CreateRemoteThread, WinInet), час компіляції.\n"
  "3) Рядки: URL, IP, шляхи, ключі реєстру. 4) Цифровий підпис і видавець. 5) YARA-правила для класифікації."),
 ("Аналіз фішингового листа (EML)",
  ["фішинг", "phishing", "eml", "лист", "email", "received", "spf", "dkim", "dmarc", "вкладення"],
  "1) Заголовки Received знизу вгору — реальний шлях і IP відправника.\n"
  "2) Authentication-Results: SPF/DKIM/DMARC. Невідповідність From/Return-Path/Reply-To.\n"
  "3) Вкладення — хеш і статичний аналіз; посилання — розгорни й перевір репутацію домену."),
 ("Висновок/звіт експерта",
  ["звіт", "висновок", "report", "документування", "докази", "ланцюг", "chain of custody"],
  "1) Структура: запитання → методи й інструменти → факти з посиланням на джерело → висновок.\n"
  "2) Відокремлюй встановлені факти від припущень (вказуй ступінь упевненості).\n"
  "3) Хеші доказів, ланцюг передачі, версії інструментів. Без оцінок поза компетенцією."),
 ("Інцидент на Linux",
  ["linux", "ubuntu", "auth.log", "secure", "bash_history", "cron", "systemd", "sudo", "ssh"],
  "1) /var/log/auth.log (secure): входи SSH, sudo, невдалі спроби з IP.\n"
  "2) ~/.bash_history, /tmp, /dev/shm; нові користувачі в /etc/passwd; ключі в ~/.ssh/authorized_keys.\n"
  "3) Закріплення: crontab, /etc/cron.*, systemd-служби, rc.local. Перевір змінені бінарники (пакетний менеджер -V)."),
]

data = {"version": 1, "skills": []}
if os.path.exists(OUT):
    data = json.load(open(OUT, encoding="utf-8"))
    data["skills"] = [s for s in data["skills"] if s.get("source") != "curated"]  # оновити кураторські
now = int(time.time())
for i, (title, trig, body) in enumerate(S):
    data["skills"].append({"id": "cur-%02d" % (i + 1), "scope": "global", "title": title, "triggers": trig,
                           "body": body, "source": "curated", "status": "approved", "created": now, "uses": 0})
json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
os.chmod(OUT, 0o666)
print("кураторських скілів:", len(S), "| усього:", len(data["skills"]))
