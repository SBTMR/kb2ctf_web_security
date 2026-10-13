# Pinger

Стек: Python / Flask. Сложность: Basic.
Prerequisites: Executable, arguments, shell command strings.

## Обычный сценарий

IP Pinger: укажите локальный адрес в форме и получите текстовый результат обычной диагностики. Исходный API /api/pinger принимает поле ip и возвращает message.

## Архитектура и учебная цель

ip → shell command string. Исходный subprocess.run запускает одну shell string, без added timeout или output cap.
Возвращаются исходные stderr либо stdout в message. Новый UI показывает ответ как текст.
Общий новый UI не меняет основную учебную причину ошибки оригинала.
Flags provisioned локально; формата KB2CTF{...}, исключены из source и образов.

## Запуск и reset

Из корня repository:

~~~sh
python tools/lab.py init
docker compose -f tasks/command-injection/compose.yaml up -d --build --wait
python tools/lab.py reset command-injection
docker compose -f tasks/command-injection/compose.yaml down
~~~

Либо python tools/lab.py up command-injection. Требуются Python 3.11+ и работающий Docker с Linux containers.
Задача запускается собственным Compose project, не запускает соседние задания.
Состояние сбрасывается только у неё; локальный flag сохраняется.

## Готовность

Критерии готовности: normal flow, input errors и healthcheck; отдельный Docker-запуск и scoped reset.
Текущий статус фактических проверок указан в ../../docs/VERIFICATION.md.
Причина основной ошибки сопоставима с безопасным вариантом в FIX.md. HINTS.md содержит только концептуальные подсказки.
