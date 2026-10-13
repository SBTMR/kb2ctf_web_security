# Pinger Deluxe Edition

Стек: Python / Flask. Сложность: Intermediate.
Prerequisites: Pinger, отсутствие output и observable state.

## Обычный сценарий

Тот же IP Pinger и /api/pinger с ip. Ответ сообщает только завершение, stdout/stderr скрыты. Observer показывает состояние текущей попытки; обычный ping marker не создаёт.

## Архитектура и учебная цель

Та же Command Injection, затем output отсутствует → локальное observable state → подтверждение выполнения. Marker в выделенной области, привязан к server-generated attempt; старые markers не учитываются.
Как у исходного Pinger, используется прямой run без input length filter, process wrapper или timeout. Shell-соединения, listeners и callbacks отсутствуют.
Общий новый UI не меняет основную учебную причину ошибки оригинала.
Flags provisioned локально; формата KB2CTF{...}, исключены из source и образов.

## Запуск и reset

Из корня repository:

~~~sh
python tools/lab.py init
docker compose -f tasks/blind-rce/compose.yaml up -d --build --wait
python tools/lab.py reset blind-rce
docker compose -f tasks/blind-rce/compose.yaml down
~~~

Либо python tools/lab.py up blind-rce. Требуются Python 3.11+ и работающий Docker с Linux containers.
Задача запускается собственным Compose project, не запускает соседние задания.
Состояние сбрасывается только у неё; локальный flag сохраняется.

## Готовность

Критерии готовности: normal flow, input errors и healthcheck; отдельный Docker-запуск и scoped reset.
Текущий статус фактических проверок указан в ../../docs/VERIFICATION.md.
Причина основной ошибки сопоставима с безопасным вариантом в FIX.md. HINTS.md содержит только концептуальные подсказки.
