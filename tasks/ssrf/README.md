# Web Sheriff

Стек: Python / Flask / Requests + Go internal service. Сложность: Intermediate.
Prerequisites: HTTP clients/servers, URLs, private networks.

## Обычный сценарий

URL Sender: получите страницу controlled sample-site из формы. При необходимости добавьте обычные HTTP headers. Исходный API /api/send принимает url и headers, возвращает текст в message.

## Архитектура и учебная цель

User → Public Flask Backend → private Go Internal Service. Пользователь задаёт destination серверного HTTP client; destination allowlist отсутствует. Internal Service не опубликован наружу, использует исходную Authorization-проверку. sample-site обслуживает normal flow без интернета.
Gateway использует исходный requests.get: обычные redirects/text decoding, без добавленных URL/header filters и response/time limits.
Общий новый UI не меняет основную учебную причину ошибки оригинала.
Flags provisioned локально; формата KB2CTF{...}, исключены из source и образов.

## Запуск и reset

Из корня repository:

~~~sh
python tools/lab.py init
docker compose -f tasks/ssrf/compose.yaml up -d --build --wait
python tools/lab.py reset ssrf
docker compose -f tasks/ssrf/compose.yaml down
~~~

Либо python tools/lab.py up ssrf. Требуются Python 3.11+ и работающий Docker с Linux containers.
Задача запускается собственным Compose project, не запускает соседние задания.
Состояние сбрасывается только у неё; локальный flag сохраняется.

## Готовность

Критерии готовности: normal flow, input errors и healthcheck; отдельный Docker-запуск и scoped reset.
Текущий статус фактических проверок указан в ../../docs/VERIFICATION.md.
Причина основной ошибки сопоставима с безопасным вариантом в FIX.md. HINTS.md содержит только концептуальные подсказки.
