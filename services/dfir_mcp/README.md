# dfir-mcp — справи бота як інструменти MCP для Agent (CLI)

Один мозок, два входи: клієнт — через Telegram-бота, аналітик — через Agent у терміналі,
обидва бачать ті самі дані й знахідки детекторів. Сервіс **лише читає**.

| | |
|---|---|
| Адреса | `http://CHANGE_ME_DFIR_LINK_IP:8080/mcp` (через WireGuard; nginx uploader → `dfir-mcp:8000/mcp`) |
| Транспорт | MCP Streamable HTTP (`mcp==1.30.0`; клієнту потрібен `mcp<2`) |
| Доступ | `Authorization: Bearer <token>`; токени — sha256 у `state/mcp/mcp_tokens.json` |
| База | окрема роль `dfir_mcp`: SELECT, read-only, statement_timeout 60 с, без таблиць користувачів/облікових даних/аудиту |
| Журнал | `state/mcp/mcp_audit.jsonl` — хто, інструмент, справа, аргументи, мс, ok |

Інструменти: `list_cases`, `case_overview`, `threat_findings`, `sql_query`, `search_text`,
`timeline`, `case_report`. Порожній результат повертається явно як `EMPTY: …` з підказкою,
що перевірити (урок журналу розслідування: 29 % порожніх SQL у агента бота).

Токени:
```
docker exec dfir-mcp python /srv/mcp_tokens.py add "analyst-x" --cases 14_04_2026_a,02_09_2026_b
docker exec dfir-mcp python /srv/mcp_tokens.py list
docker exec dfir-mcp python /srv/mcp_tokens.py disable "analyst-x"
```

Agent (`the MCP client config`):
```yaml
mcp_servers:
  dfir:
    url: http://CHANGE_ME_DFIR_LINK_IP:8080/mcp
    headers:
      Authorization: "Bearer <token>"
    timeout: 300
```
Перевірка: the MCP client test command → `Tools discovered: 7`.

Перевірено 18.10.2026: протокол через nginx (7 інструментів; токен на одну справу бачить лише її;
DELETE і `bot_users` відхилено; без токена 401) і наскрізно справжнім MCP-клієнтом + agent-30b:
сам викликав `list_cases` → `case_overview` і відповів правильно.
