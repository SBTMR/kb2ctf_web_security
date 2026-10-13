# Headers / HTTP Lab

Стек: Python / Flask. Сложность: Intro.
Prerequisites: HTTP methods, headers, JSON body.

## Обычный сценарий

Откройте исходную страницу You want some flags? Приложение проверяет method, header и body запроса независимо. Нового check-in сценария нет.

## Архитектура и учебная цель

Клиентский HTTP-запрос → route и проверки исходного протокола. Это вводная protocol task.
Общий новый UI не меняет основную учебную причину ошибки оригинала.
Flags provisioned локально; формата KB2CTF{...}, исключены из source и образов.

## Запуск и reset

Из корня repository:

~~~sh
python tools/lab.py init
docker compose -f tasks/headers/compose.yaml up -d --build --wait
python tools/lab.py reset headers
docker compose -f tasks/headers/compose.yaml down
~~~

Либо python tools/lab.py up headers. Требуются Python 3.11+ и работающий Docker с Linux containers.
Задача запускается собственным Compose project, не запускает соседние задания.
Состояние сбрасывается только у неё; локальный flag сохраняется.

## Готовность

Критерии готовности: normal flow, input errors и healthcheck; отдельный Docker-запуск и scoped reset.
Текущий статус фактических проверок указан в ../../docs/VERIFICATION.md.
Причина основной ошибки сопоставима с безопасным вариантом в FIX.md. HINTS.md содержит только концептуальные подсказки.
