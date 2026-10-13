# Burger Storage

Стек: Python / Flask. Сложность: Basic.
Prerequisites: Accounts/sessions, filesystem paths.

## Обычный сценарий

Зарегистрируйтесь и войдите. В хранилище уже есть исходный burger.jpg. Загрузите небольшой файл через /upload и скачайте через /download. Сохраняются отдельные upload/download forms и поле filename.

## Архитектура и учебная цель

Пользовательское filename → filesystem read. Основная ошибка — отсутствие canonical containment в download. Upload сохраняет исходную normpath/startswith проверку; download использует исходный inline send_file.
Добавленные фильтры имён, размеры и квоты отсутствуют. Пароли хешируются исходным SHA-256.
Общий новый UI не меняет основную учебную причину ошибки оригинала.
Flags provisioned локально; формата KB2CTF{...}, исключены из source и образов.

## Запуск и reset

Из корня repository:

~~~sh
python tools/lab.py init
docker compose -f tasks/path-traversal/compose.yaml up -d --build --wait
python tools/lab.py reset path-traversal
docker compose -f tasks/path-traversal/compose.yaml down
~~~

Либо python tools/lab.py up path-traversal. Требуются Python 3.11+ и работающий Docker с Linux containers.
Задача запускается собственным Compose project, не запускает соседние задания.
Состояние сбрасывается только у неё; локальный flag сохраняется.

## Готовность

Критерии готовности: normal flow, input errors и healthcheck; отдельный Docker-запуск и scoped reset.
Текущий статус фактических проверок указан в ../../docs/VERIFICATION.md.
Причина основной ошибки сопоставима с безопасным вариантом в FIX.md. HINTS.md содержит только концептуальные подсказки.
