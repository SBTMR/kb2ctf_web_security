# Senior JWT Engineer

Стек: Python / Flask / PyJWT. Сложность: Basic.
Prerequisites: Cookies, JSON, структура JWT и signature.

## Обычный сценарий

Зарегистрируйтесь, войдите и откройте /flag. Обычный пользователь получает исходное сообщение о доступе администратора. Cookie называется flag_token, единственный создаваемый claim — username.
Signing key и простое хранение паролей в памяти взяты из оригинала; обязательного срока токенов и дополнительных password rules нет.

## Архитектура и учебная цель

Client token → server signature validation → admin authorization. Signing secret намеренно присутствует в jwtutil.py; config export из прежней реализации удалён.
Общий новый UI не меняет основную учебную причину ошибки оригинала.
Flags provisioned локально; формата KB2CTF{...}, исключены из source и образов.

## Запуск и reset

Из корня repository:

~~~sh
python tools/lab.py init
docker compose -f tasks/jwt/compose.yaml up -d --build --wait
python tools/lab.py reset jwt
docker compose -f tasks/jwt/compose.yaml down
~~~

Либо python tools/lab.py up jwt. Требуются Python 3.11+ и работающий Docker с Linux containers.
Задача запускается собственным Compose project, не запускает соседние задания.
Состояние сбрасывается только у неё; локальный flag сохраняется.

## Готовность

Критерии готовности: normal flow, input errors и healthcheck; отдельный Docker-запуск и scoped reset.
Текущий статус фактических проверок указан в ../../docs/VERIFICATION.md.
Причина основной ошибки сопоставима с безопасным вариантом в FIX.md. HINTS.md содержит только концептуальные подсказки.
