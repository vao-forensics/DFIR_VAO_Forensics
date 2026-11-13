# -*- coding: utf-8 -*-
"""Fast-path FACT SHEET — deterministic, no LLM. One markdown per case with the evidence an
analyst needs first, section by section, and an explicit «АРТЕФАКТ ВІДСУТНІЙ» line whenever the
source is not in the database (absence of evidence != evidence of absence).

Usage (inside case-maintainer):
  python /app/analysis/factsheet.py <case_key> [<case_key> ...] [--out /data/state/truth/factsheets]
  python /app/analysis/factsheet.py --all
"""
import sys, io, os, re, datetime
sys.path.insert(0, '/app')
import psycopg2
from core.config import PG_DSN
try:
    from analysis.threat_detect import _NOTE_SQL_UNION as _NOTE_SQL
except Exception:
    _NOTE_SQL = '(how_to_decrypt|readme_for_decrypt|restore-my-files|recover.?files|decrypt_instruction|_readme\\.txt|help_decrypt)'

OUT = '/data/state/truth/factsheets'
SEC_TOP = 12

RAT_FAM = [('AnyDesk', 'anydesk'), ('TeamViewer', 'teamviewer'), ('LiteManager', 'litemanager|romserver|romfusclient|romviewer'),
           ('RMS / Remote Utilities', 'remote manipulator|remote utilities|rutserv|rfusclient'), ('RustDesk', 'rustdesk'),
           ('Ammyy', 'ammyy'), ('Supremo', 'supremo'), ('Splashtop', 'splashtop'), ('ScreenConnect', 'screenconnect|connectwise'),
           ('MeshAgent', 'meshagent|meshcentral'), ('Radmin', 'radmin'), ('VNC', 'ultravnc|tightvnc|realvnc|winvnc|tvnserver|vncviewer'),
           ('DWAgent', 'dwagent'), ('Atera', r'\yatera\y'), ('Chrome Remote Desktop', 'remoting_host'), ('Quick Assist', 'quickassist')]
TUNNEL_RX = r'(ngrok|frpc|frps|chisel|cloudflared|plink|rdpwrap|rdpwinst|rdpconf|\ytor\y|proxifier|3proxy|socat|stunnel|pinggy|bore\.exe|tailscale|zerotier|wireguard|softether|openvpn|nssm)'
LOLBIN_RX = r'(-enc\y|-encodedcommand|frombase64string|\yiex\y|invoke-expression|downloadstring|downloadfile|net\.webclient|invoke-webrequest|certutil[^\n]{0,40}(-urlcache|-decode)|bitsadmin|mshta|regsvr32[^\n]{0,30}/i:|rundll32[^\n]{0,40}javascript|wmic[^\n]{0,30}process[^\n]{0,10}call|-w\s*hidden|-windowstyle\s*hidden|invoke-mimikatz|sekurlsa|schtasks[^\n]{0,20}/create|reg[^\n]{0,10}add[^\n]{0,60}\\run)'
USERWRITE_RX = r'(temp|appdata|downloads|public|desktop|documents|programdata|perflogs|recycle)'
VENDOR_SVC_RX = r'(microsoft|windows|intel|nvidia|amd|realtek|dell|hp|lenovo|asus|apple|google|mozilla|adobe|kaspersky|eset|avast|avg|bitdefender|sophos|cisco|vmware|virtualbox|oracle|logitech|synaptics|qualcomm|broadcom|citrix|teamviewer|anydesk|defender|mpksl|wd\\|drivers\\)'


def q(cur, sql, args=()):
    try:
        cur.execute(sql, args)
        return cur.fetchall()
    except Exception as e:
        try:
            cur.connection.rollback()
        except Exception:
            pass
        return [('(помилка запиту: %s)' % str(e)[:80],)]


def ts(v):
    try:
        return v.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(v)[:19]


def sec(L, title):
    L.append('')
    L.append('## %s' % title)


def absent(L, what):
    L.append('- ⚠ АРТЕФАКТ ВІДСУТНІЙ: %s — висновків у цьому напрямі зробити не можна.' % what)


def rows(L, rs, fmt, limit=SEC_TOP, empty='- (нічого не знайдено)'):
    if not rs or (len(rs) == 1 and str(rs[0][0]).startswith('(помилка')):
        L.append(empty if not rs else '- %s' % rs[0][0])
        return
    for r in rs[:limit]:
        try:
            L.append('- ' + fmt(r))
        except Exception as e:
            L.append('- (рядок не відформатовано: %s)' % str(e)[:60])
    if len(rs) > limit:
        L.append('- … ще %d' % (len(rs) - limit))


def build(ck, cur):
    L = ['# FACT SHEET — %s' % ck, '_Детермінований зріз доказів (fast path, без ШІ), %s_' % datetime.datetime.now().strftime('%Y-%m-%d %H:%M')]
    K = (ck,)
    cnt = {}
    for t in ('event_logs_v2', 'program_exec_v2', 'filesystem_v2', 'raw_fallback_v2', 'srum_v2', 'tool_alerts_v2'):
        r = q(cur, 'SELECT count(*) FROM %s WHERE case_key=%%s' % t, K)
        cnt[t] = r[0][0] if r and isinstance(r[0][0], int) else 0
    L.append('- Рядків: ' + ', '.join('%s=%s' % (k.replace('_v2', ''), v) for k, v in cnt.items()))
    fams = q(cur, "SELECT parser_family, count(*) FROM raw_fallback_v2 WHERE case_key=%s GROUP BY 1 ORDER BY 2 DESC", K)
    L.append('- raw families: ' + ', '.join('%s=%s' % (a, b) for a, b in fams[:25]) if fams and not str(fams[0][0]).startswith('(') else '- raw families: немає')
    try:
        from analysis.coverage_model import evidence_sources, blind_spots
        bs = blind_spots(evidence_sources(ck, cur.connection))
        L.append('- Сліпі зони (coverage_model): ' + (', '.join(b['key'] for b in bs) if bs else 'немає'))
    except Exception as e:
        L.append('- coverage_model: помилка %s' % str(e)[:60])
    span = q(cur, "SELECT min(event_ts), max(event_ts) FROM event_logs_v2 WHERE case_key=%s AND event_ts > '2000-01-01'", K)
    if span and span[0][0]:
        L.append('- Діапазон подій: %s → %s' % (ts(span[0][0]), ts(span[0][1])))

    # 1 system / users
    sec(L, '1. Система / користувачі')
    rows(L, q(cur, "SELECT coalesce(computer,'?'), count(*) FROM event_logs_v2 WHERE case_key=%s GROUP BY 1 ORDER BY 2 DESC LIMIT 5", K), lambda r: 'хост `%s` (%s подій)' % (r[0], r[1]), 5)
    rows(L, q(cur, "SELECT coalesce(target_user,'?'), count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=4624 AND coalesce(target_user,'') !~* '(\\$$|^system$|^local service|^network service|^dwm-|^umfd-|^anonymous)' GROUP BY 1 ORDER BY 2 DESC LIMIT 10", K), lambda r: 'акаунт з входами `%s` (%s×4624)' % (r[0], r[1]), 10)
    env = q(cur, "SELECT left(payload::text, 300) FROM raw_fallback_v2 WHERE case_key=%s AND parser_family IN ('environment','system_profile','collector_self') LIMIT 3", K)
    rows(L, env, lambda r: 'середовище: %s' % r[0], 3, empty='- профіль ОС у raw-даних відсутній (старий збирач)')

    # 2 logons / RDP / SMB
    sec(L, '2. Входи / RDP / SMB')
    if not cnt['event_logs_v2']:
        absent(L, 'журнали подій (event_logs)')
    rows(L, q(cur, "SELECT coalesce(logon_type,'?'), count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=4624 GROUP BY 1 ORDER BY 2 DESC", K), lambda r: '4624 type %s: %s' % (r[0], r[1]), 8)
    rdp = q(cur, """SELECT coalesce(remote_host,'?'), string_agg(DISTINCT coalesce(target_user,'?'), ','), count(*), min(event_ts), max(event_ts)
                    FROM event_logs_v2 WHERE case_key=%s AND ((event_id IN (1149,21,25) AND source_file ILIKE '%%TerminalServices%%') OR (event_id=4624 AND logon_type='10'))
                    GROUP BY 1 ORDER BY 3 DESC LIMIT 12""", K)
    rows(L, rdp, lambda r: 'RDP з `%s` як %s: %s сесій, %s → %s' % (r[0][:45], r[1][:50], r[2], ts(r[3]), ts(r[4])), 12, empty='- RDP-сесій (1149/21/25/4624-10) не зафіксовано')
    rows(L, q(cur, "SELECT coalesce(remote_host,'?'), coalesce(target_user,'?'), count(*), min(event_ts) FROM event_logs_v2 WHERE case_key=%s AND event_id=4625 GROUP BY 1,2 ORDER BY 3 DESC LIMIT 6", K), lambda r: 'невдалі входи 4625 з `%s` як `%s`: %s (перший %s)' % (r[0][:40], r[1][:30], r[2], ts(r[3])), 6, empty='- невдалих входів 4625 немає')
    rows(L, q(cur, "SELECT event_id, count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (5140,5145,4776,4768,4769,4771) GROUP BY 1 ORDER BY 1", K), lambda r: 'SMB/Kerberos/NTLM EID %s: %s' % (r[0], r[1]), 8, empty='- SMB/Kerberos подій (5140/5145/4768/4769/4776) немає')

    # 3 execution
    sec(L, '3. Запуски (Prefetch/Amcache/ShimCache/BAM/4688)')
    if not cnt['program_exec_v2']:
        absent(L, 'артефакти виконання (program_exec)')
    rows(L, q(cur, "SELECT regexp_replace(source_file,'^[0-9]+_',''), count(*) FROM program_exec_v2 WHERE case_key=%s GROUP BY 1 ORDER BY 2 DESC", K), lambda r: '%s: %s' % (r[0][:60], r[1]), 8)
    n4688 = q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=4688", K)
    L.append('- 4688 (створення процесів): %s%s' % (n4688[0][0], '' if n4688[0][0] else ' — аудит процесів вимкнений, ланцюжок батько→дитина недоступний'))
    rows(L, q(cur, """SELECT min(event_ts), lower(coalesce(full_path, executable_name)), count(*) FROM program_exec_v2
                       WHERE case_key=%s AND event_ts IS NOT NULL AND lower(coalesce(full_path,'')) ~ %s
                         AND lower(coalesce(full_path,'')) !~ '(setup|install|update|vcredist|unins|redist|\\\\windowsapps\\\\|onedrive|\\\\adobe|\\\\google\\\\|\\\\microsoft\\\\|package cache|kape|dfirtriage|dfir_collector|dumpit|ftkimager|magnet|autoruns|procexp|cports|gkape|vao_|winpmem|belkasoft|7za\\.exe)'
                       GROUP BY 2 ORDER BY 1 DESC LIMIT 15""", (ck, USERWRITE_RX)),
         lambda r: '%s `%s` (%s)' % (ts(r[0]), r[1][:100], r[2]), 15, empty='- запусків із користувацьких/тимчасових тек не знайдено')

    # 4 PowerShell / LOLBin
    sec(L, '4. PowerShell / cmd / LOLBin')
    ps = q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND source_file ILIKE '%%PowerShell%%'", K)
    if not ps[0][0]:
        absent(L, 'журнали PowerShell')
    rows(L, q(cur, """SELECT substring(lower(command_line) from %s) AS pat, count(*), min(event_ts), min(left(command_line, 140))
                       FROM event_logs_v2 WHERE case_key=%s AND coalesce(command_line,'') <> '' AND lower(command_line) ~ %s
                       GROUP BY 1 ORDER BY 2 DESC LIMIT 12""", (LOLBIN_RX, ck, LOLBIN_RX)),
         lambda r: '`%s` ×%s, перший %s — %s' % (r[0], r[1], ts(r[2]), str(r[3]).replace('\n', ' ')[:110]), 12, empty='- LOLBin/обфускованих команд не знайдено')

    # 5 downloads / Zone.Identifier
    sec(L, '5. Завантаження / Zone.Identifier / браузер')
    zi = q(cur, """SELECT event_ts, file_name, left(coalesce(payload->>'HostUrl', payload->>'ReferrerUrl', payload->>'url', ''),80), left(parent_path,60)
                   FROM filesystem_v2 WHERE case_key=%s AND (ltrim(lower(extension),'.')='identifier' OR file_name ILIKE '%%:Zone.Identifier%%')
                   ORDER BY event_ts DESC NULLS LAST LIMIT 12""", K)
    rows(L, zi, lambda r: '%s `%s` ← %s (%s)' % (ts(r[0]), str(r[1]).replace(':Zone.Identifier', '')[:60], r[2] or 'URL не збережено', r[3]), 12, empty='- Zone.Identifier (MOTW) записів немає')
    rows(L, q(cur, "SELECT parser_family, count(*) FROM raw_fallback_v2 WHERE case_key=%s AND parser_family LIKE 'browser%%' GROUP BY 1", K), lambda r: '%s: %s' % (r[0], r[1]), 6, empty='- історії браузерів немає')
    rows(L, q(cur, """SELECT substring(payload::text from 'https?://([^/"\\\\ ]+)') AS host, count(*) FROM raw_fallback_v2
                       WHERE case_key=%s AND parser_family IN ('browser_downloads','browser_history') GROUP BY 1 ORDER BY 2 DESC LIMIT 10""", K),
         lambda r: 'домен `%s`: %s' % (r[0], r[1]), 10, empty='')

    # 6 Defender / AV
    sec(L, '6. Defender / AV')
    dfn = q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND source_file ILIKE '%%Defender%%'", K)
    if not dfn[0][0]:
        absent(L, 'журнал Windows Defender')
    rows(L, q(cur, """SELECT coalesce(substring(payload::text from '(Trojan|HackTool|Behavior|PUA|Backdoor|Ransom|VirTool|Exploit|TrojanDownloader|TrojanDropper|Program|Tool|Virus|Worm)[:/][A-Za-z0-9_/.!-]+'), 'детекція без назви'), count(*), min(event_ts), max(event_ts)
                       FROM event_logs_v2 WHERE case_key=%s AND event_id IN (1116,1117) GROUP BY 1 ORDER BY 2 DESC LIMIT 12""", K),
         lambda r: '%s ×%s (%s → %s)' % (r[0], r[1], ts(r[2]), ts(r[3])), 12, empty='- детекцій 1116/1117 немає')
    rows(L, q(cur, "SELECT event_id, count(*), min(event_ts) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (5001,5004,5007,5010,5012,5013) GROUP BY 1 ORDER BY 1", K), lambda r: 'зміна захисту EID %s ×%s (перша %s)' % (r[0], r[1], ts(r[2])), 8, empty='- подій вимкнення/зміни захисту немає')
    rows(L, q(cur, "SELECT min(event_ts), left(command_line,150) FROM event_logs_v2 WHERE case_key=%s AND lower(command_line) ~ '(set|add)-mppreference\\s+-(exclusion|disable|mapsreporting|submitsamples|severethreat|highthreat|moderatethreat|lowthreat)' AND lower(command_line) !~ 'cmdletization' GROUP BY 2 ORDER BY 1 LIMIT 6", K), lambda r: '%s Set-MpPreference: %s' % (ts(r[0]), str(r[1]).replace('\n', ' ')), 6, empty='- Set-MpPreference у командних рядках немає')
    rows(L, q(cur, "SELECT parser_family, count(*) FROM raw_fallback_v2 WHERE case_key=%s AND parser_family IN ('defender_exclusions','other_antivirus') GROUP BY 1", K), lambda r: '%s: %s' % (r[0], r[1]), 4, empty='')

    # 7 services / tasks / persistence
    sec(L, '7. Служби / завдання / закріплення')
    svc = q(cur, """SELECT event_ts, coalesce(payload->>'PayloadData1',''), left(coalesce(payload->>'PayloadData2', payload->>'PayloadData3',''),90)
                    FROM event_logs_v2 WHERE case_key=%s AND event_id=7045 AND lower(payload::text) !~ %s ORDER BY event_ts DESC LIMIT 12""", (ck, VENDOR_SVC_RX))
    rows(L, svc, lambda r: '%s служба %s → %s' % (ts(r[0]), r[1][:50], r[2]), 12, empty='- нових не-вендорських служб (7045) немає')
    rows(L, q(cur, "SELECT event_ts, coalesce(target_user,''), left(coalesce(substring(payload::text from '(?i)task ?name[^,]{0,4}[:=] ?([^,]{1,80})'), payload->>'PayloadData1', ''),100) FROM event_logs_v2 WHERE case_key=%s AND (event_id=4698 OR (event_id=106 AND source_file ILIKE '%%TaskScheduler%%')) ORDER BY event_ts DESC LIMIT 10", K), lambda r: '%s завдання %s %s' % (ts(r[0]), r[1][:30], r[2]), 10, empty='- створення запланованих завдань (4698/106) немає')
    reg = q(cur, """SELECT left(payload::text, 170) FROM raw_fallback_v2 WHERE case_key=%s AND parser_family IN ('registry','regripper_software','regripper_ntuser','autoruns')
                    AND payload::text ~* '(currentversion..run|runonce|userinit|image file execution|winlogon..shell)' AND payload::text ~* '(appdata|temp|users|programdata|public)' LIMIT 8""", K)
    rows(L, reg, lambda r: 'реєстр: %s' % r[0].replace('\n', ' '), 8, empty='- автозапусків у реєстрі з користувацьких тек не знайдено (або реєстр не зібрано — див. сліпі зони)')

    # 8 remote tools
    sec(L, '8. Засоби віддаленого доступу')
    found = []
    for fam, rx in RAT_FAM:
        r = q(cur, """SELECT min(event_ts), min(coalesce(full_path, executable_name)), count(*) FROM program_exec_v2 WHERE case_key=%s AND event_ts IS NOT NULL
                      AND lower(coalesce(full_path,'')||' '||coalesce(executable_name,'')) ~ %s AND lower(coalesce(full_path,'')) !~ '(unins|setup|install)'""", (ck, rx))
        if r and r[0] and r[0][0] and not str(r[0][0]).startswith('('):
            found.append((r[0][0], fam, r[0][1], r[0][2]))
    rows(L, sorted(found), lambda r: '%s **%s** `%s` (%s)' % (ts(r[0]), r[1], str(r[2])[:80], r[3]), 16, empty='- засобів віддаленого доступу у запусках не знайдено')

    # 9 tunneling / proxy
    sec(L, '9. Тунелі / проксі')
    rows(L, q(cur, "SELECT min(event_ts), lower(coalesce(full_path, executable_name)), count(*) FROM program_exec_v2 WHERE case_key=%s AND lower(coalesce(full_path,'')||' '||coalesce(executable_name,'')) ~ %s GROUP BY 2 ORDER BY 1 LIMIT 10", (ck, TUNNEL_RX)),
         lambda r: '%s `%s` (%s)' % (ts(r[0]), r[1][:100], r[2]), 10, empty='- тунельних/проксі-інструментів у запусках немає')
    rows(L, q(cur, "SELECT min(event_ts), left(command_line,140) FROM event_logs_v2 WHERE case_key=%s AND lower(command_line) ~ %s GROUP BY 2 ORDER BY 1 LIMIT 5", (ck, TUNNEL_RX)), lambda r: '%s cmd: %s' % (ts(r[0]), str(r[1]).replace('\n', ' ')), 5, empty='')

    # 10 lateral movement
    sec(L, '10. Латеральний рух')
    rows(L, q(cur, "SELECT coalesce(remote_host,'?'), count(*), min(event_ts) FROM event_logs_v2 WHERE case_key=%s AND event_id=4624 AND logon_type='3' AND coalesce(remote_host,'') !~ '^(-|::1|127\\.|$)' GROUP BY 1 ORDER BY 2 DESC LIMIT 8", K), lambda r: 'мережеві входи type 3 з `%s`: %s (перший %s)' % (r[0][:45], r[1], ts(r[2])), 8, empty='- мережевих входів type 3 з віддалених хостів немає')
    rows(L, q(cur, "SELECT min(event_ts), left(coalesce(command_line, process_name),120), count(*) FROM event_logs_v2 WHERE case_key=%s AND lower(coalesce(command_line,'')||coalesce(process_name,'')||coalesce(payload::text,'')) ~ '(psexec|psexesvc|paexec|wmic[^\\n]{0,20}/node|winrs|enter-pssession|invoke-command[^\\n]{0,30}-computername|net use \\\\\\\\)' GROUP BY 2 ORDER BY 1 LIMIT 6", K), lambda r: '%s %s (%s)' % (ts(r[0]), str(r[1]).replace('\n', ' '), r[2]), 6, empty='- PsExec/WMI/WinRM слідів у логах немає')

    # 11 accounts
    sec(L, '11. Облікові записи')
    rows(L, q(cur, "SELECT event_ts, event_id, coalesce(target_user,''), left(coalesce(payload->>'PayloadData1',''),80) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4720,4722,4724,4726,4728,4732,4756) ORDER BY event_ts LIMIT 12", K), lambda r: '%s EID %s `%s` %s' % (ts(r[0]), r[1], r[2][:40], r[3]), 12, empty='- створення/зміни акаунтів (4720/4722/4728/4732) немає')

    # 12 staging / exfil
    sec(L, '12. Архівування / staging / ексфільтрація')
    rows(L, q(cur, "SELECT min(event_ts), left(command_line,140), count(*) FROM event_logs_v2 WHERE case_key=%s AND lower(command_line) ~ '((7z|7za|rar|winrar)(\\.exe)?\\s+a\\s|compress-archive|rclone\\s+(copy|sync)|megacmd|mega\\.nz|curl[^\\n]{0,40}\\s-T\\s|--upload-file|winscp[^\\n]{0,40}\\yput\\y)' GROUP BY 2 ORDER BY 1 LIMIT 6", K), lambda r: '%s %s (%s)' % (ts(r[0]), str(r[1]).replace('\n', ' '), r[2]), 6, empty='- команд архівування/вивантаження немає')
    rows(L, q(cur, "SELECT event_ts, file_name, left(parent_path,60), (payload->>'FileSize')::bigint FROM filesystem_v2 WHERE case_key=%s AND ltrim(lower(extension),'.') IN ('7z','rar','zip') AND coalesce((payload->>'FileSize')::bigint,0) > 50000000 AND lower(parent_path) ~ '(users|temp|public|programdata)' ORDER BY 4 DESC LIMIT 6", K), lambda r: '%s архів `%s` у %s, %d МБ' % (ts(r[0]), r[1][:50], r[2], (r[3] or 0) // 1048576), 6, empty='- великих архівів (>50 МБ) у користувацьких теках немає')

    # 13 ransomware / wiper
    sec(L, '13. Ransomware / wiper / знищення')
    rows(L, q(cur, """SELECT ltrim(lower(extension),'.'), count(*), count(DISTINCT parent_path) FROM filesystem_v2 WHERE case_key=%s AND coalesce(extension,'') <> ''
                       AND lower(parent_path) ~ '(users|documents|desktop|shares?|data|public)' AND ltrim(lower(extension),'.') !~ '^(txt|doc[xm]?|xls[xm]?|ppt[x]?|pdf|jpe?g|png|gif|bmp|mp[34]|avi|mkv|zip|rar|7z|exe|dll|sys|log|ini|xml|json|html?|css|js|py|dat|db|tmp|bak|lnk|url|ico|ttf|otf|cfg|csv|msg|eml|pst|ost|odt|ods|rtf|iso|cab|msi|mov|wav|svg|webp|heic|ps1|bat|cmd|vbs|manifest|cat|inf|mui|nls|etl|evtx|pf|jar|class|cs|cpp|h|c|java|php|sql|md|yml|yaml|toml|lock|map|ts|tsx|jsx|vue|scss|less|woff2?|eot|ttc|bin|hex|img|vhd[x]?|vmdk|ova|ovf|pem|crt|key|pfx|cer|p12|der|asc|gpg|sig|torrent|nfo|sfv|par2|srt|sub|idx|ass|m4a|m4v|flac|ogg|opus|aac|wma|wmv|flv|webm|3gp|ts|m2ts|mts|vob|mpg|mpeg|rm|rmvb|swf|fla|psd|ai|eps|indd|xcf|cdr|dwg|dxf|skp|blend|fbx|obj|stl|3ds|max|ma|mb|c4d|zbr|ztl|lwo|lws|x3d|dae|gltf|glb|usd|usda|usdc|usdz|abc|vrml|wrl|step|stp|iges|igs|sat|brep|catpart|catproduct|prt|asm|sldprt|sldasm|slddrw|ipt|iam|idw|dgn|rvt|rfa|nwd|nwc|ifc)$'
                       GROUP BY 1 HAVING count(*) >= 25 ORDER BY 2 DESC LIMIT 6""", K), lambda r: 'нетипове розширення `%s`: %s файлів у %s теках' % (r[0], r[1], r[2]), 6, empty='- кластерів файлів з нетиповим розширенням (≥25) у користувацьких теках немає')
    rows(L, q(cur, "SELECT file_name, count(DISTINCT parent_path) FROM filesystem_v2 WHERE case_key=%s AND lower(file_name) ~ %s GROUP BY 1 HAVING count(DISTINCT parent_path) >= 2 ORDER BY 2 DESC LIMIT 5", (ck, _NOTE_SQL)), lambda r: 'можлива записка `%s` у %s теках' % (r[0], r[1]), 5, empty='- повторюваних записок-нотаток немає')
    rows(L, q(cur, "SELECT min(event_ts), lower(executable_name), count(*) FROM program_exec_v2 WHERE case_key=%s AND lower(executable_name) ~ '(vssadmin|wbadmin|bcdedit|cipher|diskpart|reagentc|wmic)' GROUP BY 2 ORDER BY 1 LIMIT 6", K), lambda r: '%s `%s` (%s)' % (ts(r[0]), r[1], r[2]), 6, empty='- утиліт знищення відновлення (vssadmin/wbadmin/bcdedit) у запусках немає')
    rows(L, q(cur, "SELECT event_ts, event_id, coalesce(target_user,''), left(coalesce(payload->>'PayloadData1',''),60) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (1074,6008,41) ORDER BY event_ts DESC LIMIT 5", K), lambda r: '%s вимкнення EID %s %s %s' % (ts(r[0]), r[1], r[2][:30], r[3]), 5, empty='- подій вимкнення (1074/6008/41) немає')
    rows(L, q(cur, "SELECT event_ts, file_name, left(parent_path,80) FROM filesystem_v2 WHERE case_key=%s AND lower(file_name) IN ('boot.wim','winpe.wim') AND lower(parent_path) !~ '(windows\\\\boot|windowsre|windows kits|winsxs|sources|servicing|package_for)' ORDER BY event_ts DESC LIMIT 4", K), lambda r: '%s WinPE-образ `%s` у %s' % (ts(r[0]), r[1], r[2]), 4, empty='')

    # 14 log clearing
    sec(L, '14. Очищення журналів / анти-форензика')
    rows(L, q(cur, "SELECT event_ts, event_id, coalesce(target_user,''), left(coalesce(payload->>'PayloadData1',''),60) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (1102,104) ORDER BY event_ts DESC LIMIT 10", K), lambda r: '%s EID %s %s %s' % (ts(r[0]), r[1], r[2][:30], r[3]), 10, empty='- очищення журналів (1102/104) не зафіксовано')
    rows(L, q(cur, "SELECT count(*), min(event_ts) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4719,4616)", K), lambda r: 'зміна політики аудиту/часу (4719/4616): %s (перша %s)' % (r[0], ts(r[1])) if r[0] else 'змін політики аудиту/часу немає', 1)
    rows(L, q(cur, "SELECT min(event_ts), left(command_line,120), count(*) FROM event_logs_v2 WHERE case_key=%s AND lower(command_line) ~ '(wevtutil[^\\n]{0,10}cl|clear-eventlog|fsutil[^\\n]{0,20}usn[^\\n]{0,10}deletejournal|sdelete|cipher[^\\n]{0,5}/w|timestomp)' GROUP BY 2 ORDER BY 1 LIMIT 5", K), lambda r: '%s %s (%s)' % (ts(r[0]), str(r[1]).replace('\n', ' '), r[2]), 5, empty='')

    # 15 USB
    sec(L, '15. USB / знімні носії')
    rows(L, q(cur, "SELECT event_id, count(*), min(event_ts), max(event_ts) FROM event_logs_v2 WHERE case_key=%s AND (event_id IN (2003,2100,2101,2102,2105,2106,6416) OR source_file ILIKE '%%DriverFrameworks-UserMode%%' OR source_file ILIKE '%%Partition%%Diagnostic%%') GROUP BY 1 ORDER BY 2 DESC LIMIT 6", K), lambda r: 'USB-подія EID %s ×%s (%s → %s)' % (r[0], r[1], ts(r[2]), ts(r[3])), 6, empty='- USB-подій у журналах немає')
    rows(L, q(cur, "SELECT left(payload::text,150) FROM raw_fallback_v2 WHERE case_key=%s AND parser_family IN ('registry','regripper_system','autoruns') AND payload::text ~* 'usbstor' AND payload::text !~* 'usbstor\\.sys' LIMIT 5", K), lambda r: 'USBSTOR: %s' % r[0].replace('\n', ' '), 5, empty='- записів USBSTOR у реєстрових даних немає (або реєстр не зібрано)')

    # 16 SRUM
    sec(L, '16. SRUM (мережева активність процесів)')
    if not cnt['srum_v2']:
        absent(L, 'SRUM')
    else:
        rows(L, q(cur, "SELECT left(payload::text, 160) FROM srum_v2 WHERE case_key=%s ORDER BY (payload->>'BytesSent')::bigint DESC NULLS LAST LIMIT 6", K), lambda r: r[0].replace('\n', ' '), 6)

    # 17 scanners
    sec(L, '17. Сканери (hayabusa / DeepBlue / THOR / loki)')
    if not cnt['tool_alerts_v2']:
        absent(L, 'сканерні алерти (tool_alerts) — сканери в цьому зборі не запускались')
    rows(L, q(cur, "SELECT coalesce(tool,'?'), coalesce(severity,'?'), left(coalesce(rule,''),70), count(*), min(event_ts) FROM tool_alerts_v2 WHERE case_key=%s AND coalesce(severity,'') IN ('critical','high','medium') GROUP BY 1,2,3 ORDER BY (CASE coalesce(severity,'?') WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END), 4 DESC LIMIT 14", K), lambda r: '%s/%s `%s` ×%s (перший %s)' % (r[0], r[1], r[2], r[3], ts(r[4])), 14, empty='- алертів рівня medium+ немає')

    # 18 suspicious rare execution
    sec(L, '18. Рідкісні/випадкові запуски')
    rows(L, q(cur, """SELECT min(event_ts), lower(coalesce(full_path, executable_name)) FROM program_exec_v2 WHERE case_key=%s AND event_ts IS NOT NULL
                       AND lower(coalesce(executable_name,'')) ~ '^[a-z0-9]{8,}\\.exe$' AND lower(coalesce(executable_name,'')) ~ '[0-9]' AND lower(coalesce(executable_name,'')) ~ '[a-z]'
                       AND lower(coalesce(full_path,'')) !~ '(windows\\\\|program files|windowsapps|installer|\\{)' GROUP BY 2 ORDER BY 1 DESC LIMIT 10""", K),
         lambda r: '%s `%s`' % (ts(r[0]), r[1][:100]), 10, empty='- виконуваних файлів із випадковими іменами поза системними теками немає')
    return '\n'.join(L) + '\n'


def main():
    args = sys.argv[1:]
    out = OUT
    if '--out' in args:
        out = args[args.index('--out') + 1]
        del args[args.index('--out'):args.index('--out') + 2]
    os.makedirs(out, exist_ok=True)
    with psycopg2.connect(PG_DSN) as c:
        c.autocommit = True
        cur = c.cursor()
        cur.execute("SET statement_timeout='120000'")
        if args[:1] == ['--all']:
            cur.execute("SELECT DISTINCT case_key FROM event_logs_v2 ORDER BY 1")
            args = [r[0] for r in cur.fetchall()]
        for ck in args:
            md = build(ck, cur)
            p = os.path.join(out, ck + '.md')
            io.open(p, 'w', encoding='utf-8').write(md)
            print('factsheet:', p, len(md.split('\n')), 'lines')


if __name__ == '__main__':
    main()
