# PentraScan

SaaS платформа автоматизированного пентестинга.

## Стек
- **Backend**: FastAPI + Python
- **Frontend**: React + TypeScript + Tailwind
- **Queue**: Celery + Redis
- **DB**: PostgreSQL
- **Scan isolation**: Docker per scan
- **Deploy**: Kali Linux + Docker Compose + Nginx

## Быстрый старт

```bash
cp .env.example .env
# заполнить .env
docker compose up -d
```

## Структура
```
pentrascan/
├── backend/    — FastAPI приложение
├── frontend/   — React приложение
├── scanner/    — Scan engine + Docker образ
├── docker/     — Docker Compose конфиги
└── docs/       — Документация
```
