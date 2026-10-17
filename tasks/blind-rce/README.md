# Pinger Deluxe Edition

Механика повторяет [Pinger Deluxe Edition из learn-web](https://github.com/FrakenboK/learn-web/tree/main/tasks/pinger-deluxe-edition):
`POST /api/pinger` принимает JSON с полем `ip` и выполняет `ping %s -c 1` через shell.
stdout и stderr захватываются, но не возвращаются клиенту. При непустом stderr ответ —
`{"message":"bebebe error"}`, иначе — `{"message":"bebebe pinged"}`.
Без поля `ip` возвращается `{"message":"The IP address was not specified"}`.
Все эти ответы имеют HTTP-статус 200. Код возврата процесса отдельно не проверяется.

Сохранено оформление KB2CTF. Дополнительных observer, marker, сессий и идентификаторов попыток нет.
Как в оригинале, приложение работает на Python 3.10 Alpine с Flask и BusyBox ping;
флаг передаётся процессу и его дочерним командам в переменной окружения `FLAG`.

## Запуск

Скопируйте всю эту папку в любое место и из неё выполните:

~~~sh
docker compose up --build
~~~

Откройте http://127.0.0.1:8087. Нужны только Docker с Linux containers и Docker Compose v2.
Порт 8087 должен быть свободен. Внутри контейнера приложение слушает порт 51338, как в оригинале.

Учебное значение `FLAG` задано в `compose.yaml`. Для своего стенда замените его и выполните
`docker compose up -d --build`. Файл `/flag.txt` не создаётся.
Участникам выдавайте адрес стенда: доступ к исходникам и истории Git позволяет найти ответы напрямую.
Стенд предназначен для локального обучения; опубликованный порт привязан к 127.0.0.1.

Остановка: Ctrl+C, затем `docker compose down`. Для сброса контейнера:
`docker compose up -d --force-recreate`.

Концептуальные подсказки — HINTS.md; причина ошибки и безопасный вариант — FIX.md.
Attribution и лицензии — NOTICE.md и файлы соответствующих зависимостей.
