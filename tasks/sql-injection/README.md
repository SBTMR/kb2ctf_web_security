# SQL Hunter

Стек: Python / Flask / SQLAlchemy / PostgreSQL. Сложность: Basic.
Prerequisites: Forms, cookies/session, основы SELECT/WHERE.

## Обычный сценарий

Зарегистрируйтесь и войдите в сервис личных заметок. Новый аккаунт не имеет заметок, как в оригинале. Учебный пользователь robert имеет исходные обычные заметки и provisioned private note.

## Архитектура и учебная цель

Username → SQL query string. Регистрация, вход и notes используют исходное построение запросов строками.
Пароли — исходный SHA-256, без дополнительных ограничений длины. Одна учебная тема — SQL Injection.
Общий новый UI не меняет основную учебную причину ошибки оригинала.
Flags provisioned локально; формата KB2CTF{...}, исключены из source и образов.

## Запуск и reset

Из корня repository:

~~~sh
python tools/lab.py init
docker compose -f tasks/sql-injection/compose.yaml up -d --build --wait
python tools/lab.py reset sql-injection
docker compose -f tasks/sql-injection/compose.yaml down
~~~

Либо python tools/lab.py up sql-injection. Требуются Python 3.11+ и работающий Docker с Linux containers.
Задача запускается собственным Compose project, не запускает соседние задания.
Состояние сбрасывается только у неё; локальный flag сохраняется.

## Готовность

Критерии готовности: normal flow, input errors и healthcheck; отдельный Docker-запуск и scoped reset.
Текущий статус фактических проверок указан в ../../docs/VERIFICATION.md.
Причина основной ошибки сопоставима с безопасным вариантом в FIX.md. HINTS.md содержит только концептуальные подсказки.
