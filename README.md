# PentraScan

SaaS платформа автоматизированного пентестинга на базе Kali Linux.

## Стек

- **Backend**: FastAPI + SQLAlchemy + Celery
- **Frontend**: React + TypeScript + Vite + Tailwind + shadcn/ui
- **Queue**: Celery + Redis
- **DB**: PostgreSQL 16
- **Scan isolation**: отдельный Docker-контейнер на каждый скан
- **Deploy**: Kali Linux + Docker Compose + Nginx + Let's Encrypt

---

## Запуск на Kali Linux

### 1. Системные зависимости

```bash
# Обновить систему
sudo apt update && sudo apt upgrade -y

# Docker
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker          # применить без перелогина

# Node.js 20 (для сборки фронта)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt install -y nodejs

# Python 3.11+
sudo apt install -y python3 python3-pip python3-venv
```

### 2. Клонировать и настроить

```bash
git clone <repo-url> pentrascan
cd pentrascan

# Создать .env из примера
cp .env.example .env
nano .env   # заполнить обязательные поля (см. ниже)
```

### 3. Обязательные поля .env

```env
# Сменить на случайные строки:
POSTGRES_PASSWORD=<strong-password>
SECRET_KEY=<output of: openssl rand -hex 32>
MSF_RPC_PASS=<strong-password>

# URL приложения (для Stripe redirect и CORS)
APP_URL=http://<your-ip-or-domain>
CORS_ORIGINS=http://<your-ip-or-domain>
```

Для получения NVD API key (увеличивает лимит запросов):
→ https://nvd.nist.gov/developers/request-an-api-key

### 4. Собрать образы и запустить

```bash
# Собрать все образы (первый раз ~15-20 минут — Kali image большой)
docker compose build

# Запустить
docker compose up -d

# Проверить статус
docker compose ps

# Применить миграции БД
docker compose exec backend alembic upgrade head
```

### 5. Открыть в браузере

```
http://localhost        — приложение (через Nginx)
http://localhost/api/docs  — Swagger UI
```

Для доступа с другой машины в сети — используй IP хоста Kali.

---

## Запуск в режиме разработки (без Docker)

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Нужны запущенные postgres и redis (можно через docker):
docker run -d --name pg -e POSTGRES_PASSWORD=password -e POSTGRES_DB=pentrascan -p 5432:5432 postgres:16-alpine
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Применить миграции
alembic upgrade head

# Запустить API
uvicorn app.main:app --reload --port 8000

# В отдельном терминале — Celery worker
celery -A app.worker worker --loglevel=info --queues=default,scans,reports
```

### Frontend

```bash
cd frontend
npm install
npm run dev    # http://localhost:5173
```

---

## Структура проекта

```
pentrascan/
├── backend/
│   ├── app/
│   │   ├── api/v1/routers/   — FastAPI роутеры
│   │   ├── core/             — config, deps, security, logging
│   │   ├── models/           — SQLAlchemy модели
│   │   ├── scanner/          — модули сканирования (31 модуль)
│   │   ├── tasks/            — Celery задачи
│   │   ├── reports/          — PDF генератор (WeasyPrint)
│   │   └── templates/        — Jinja2 HTML шаблоны отчётов
│   └── tests/                — pytest unit тесты
├── frontend/
│   └── src/
│       ├── pages/            — Dashboard, ScanDetail, Billing, Admin, DDoS...
│       └── components/       — UI компоненты
├── docker/
│   ├── scanner/Dockerfile    — Kali Linux образ со всеми инструментами
│   ├── nginx/                — nginx.conf + nginx.prod.conf (SSL)
│   └── msfrpcd/              — Metasploit RPC daemon
├── docker-compose.yml        — development
└── docker-compose.prod.yml   — production (certbot, pg_backup, SSL)
```

---

## Scanner pipeline (фазы сканирования)

| Фаза | Модуль | Инструменты |
|------|--------|-------------|
| dns_recon | dns.py | subfinder, dnsx, dnsrecon, fierce |
| osint | osint.py | Shodan, Censys, theHarvester, waybackurls |
| recon | nmap.py | nmap (SYN, -sV, -O, NSE) |
| cve_mapping | cve_mapper.py | NVD API v2, searchsploit |
| web_scan | nikto.py | nikto |
| ssl_headers | ssl_headers.py | sslyze, httpx |
| dir_scan | dirscan.py | ffuf, feroxbuster, gobuster |
| sqli_scan | sqlmap.py | sqlmap |
| xss_scan | xss.py | dalfox |
| lfi_scan | lfi.py | ffuf + manual probes |
| web_vulns | web_vulns.py | tplmap, commix, ssrfmap, corsy, smuggler, jwt_tool |
| open_services | open_services.py | TCP/HTTP direct probes |
| brute_force | hydra.py | hydra, medusa, ncrack |
| web_brute | web_brute.py | hydra HTTP-POST |
| smb_ad | smb_ad.py | enum4linux-ng, smbmap, kerbrute, impacket |
| exploit_check | msf.py | Metasploit check() |
| post_exploit | post_exploit.py | LinPEAS, pspy, LES, WinPEAS |
| privesc_linux | privesc_linux.py | GTFOBins SUID/sudo/cron |
| privesc_windows | privesc_windows.py | JuicyPotato, PrintSpoofer, UAC bypass |
| data_gather | data_gather.py | secretsdump, mimikatz, /etc/shadow |
| hash_crack | hash_crack.py | hashcat, john |
| ddos_http | ddos_http.py | asyncio flood, GoldenEye |
| ddos_slow | ddos_slow.py | Slowloris, RUDY, slowhttptest |
| ddos_network | ddos_network.py | hping3, scapy, xerxes, t50 |
| rule_engine | rule_engine.py | dedup, CVSS 3.1, attack paths |
| msf_mapping | msf_mapper.py | MSF module annotation |

---

## Тесты

```bash
cd backend
pytest tests/ -v
```

---

## Production деплой

```bash
# Сгенерировать SSL сертификат
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm certbot

# Запустить в production режиме
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Просмотр логов ошибок
docker compose exec backend cat /app/logs/errors.log
```

---

## Планы и тарифы

| Функция | Free | Pro (4 990 ₸/мес) |
|---------|------|-------------------|
| Целей | 3 total | Unlimited |
| Scan types | recon | full / vuln / web |
| Web vulns (SQLi, XSS, LFI…) | — | ✓ |
| Brute force | — | ✓ |
| Post-exploitation | — | ✓ |
| DDoS testing | — | ✓ |
| PDF отчёт (RU + EN) | ✓ | ✓ |
| Параллельных сканов | 1 | 3 |

---

## Оплата: Kaspi Pay + Stripe

Kaspi Pay для Казахстана, Stripe для международных карт.
Webhook endpoints: `/api/v1/billing/kaspi/webhook`, `/api/v1/billing/stripe/webhook`
