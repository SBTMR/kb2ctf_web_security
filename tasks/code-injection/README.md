# Inspector Gadget

Стек: Python / Flask. Сложность: Optional/Advanced.
Prerequisites: Python expressions, arithmetic, interpreter/eval.

## Обычный сценарий

Optional calculator: соберите арифметическое выражение кнопками или вводом и нажмите =. API /api/calculate принимает sign; normal result возвращается в message. Ошибки возвращают исходный message=bebebe; отсутствующее поле — Nothing to calculate.

## Архитектура и учебная цель

Недоверенное expression → прямой eval в Flask handler, как в оригинале.
Отдельный worker, timeout, expression/result limits и фильтры типов результата отсутствуют.
Это демонстрация исходной ошибки, а не sandbox-bypass задача; безопасный evaluator приведён только в FIX.
Общий новый UI не меняет основную учебную причину ошибки оригинала.
Flags provisioned локально; формата KB2CTF{...}, исключены из source и образов.

## Запуск и reset

Из корня repository:

~~~sh
python tools/lab.py init
docker compose -f tasks/code-injection/compose.yaml up -d --build --wait
python tools/lab.py reset code-injection
docker compose -f tasks/code-injection/compose.yaml down
~~~

Либо python tools/lab.py up code-injection. Требуются Python 3.11+ и работающий Docker с Linux containers.
Задача запускается собственным Compose project, не запускает соседние задания.
Состояние сбрасывается только у неё; локальный flag сохраняется.

## Готовность

Критерии готовности: normal flow, input errors и healthcheck; отдельный Docker-запуск и scoped reset.
Текущий статус фактических проверок указан в ../../docs/VERIFICATION.md.
Причина основной ошибки сопоставима с безопасным вариантом в FIX.md. HINTS.md содержит только концептуальные подсказки.
