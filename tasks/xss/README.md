# Stored XSS — Meme Forum

Небольшой мем-форум на JavaScript: Node.js 24 LTS, Express и EJS.
Сложность Basic. Prerequisites: HTML, основы JavaScript, формы, cookies и серверные сессии.
SQL, CSP nonce и обходы sandbox для этой задачи не нужны.

## Обычный сценарий

Зарегистрируйтесь, войдите, выберите локальную картинку и опубликуйте подпись.
В наборе семь предоставленных пользователем PNG-мемов, включая «График работы».
Картинки загружаются локально; исходные пропорции сохранены. Обновление набора не требует reset.
Начальная лента содержит по одному посту на каждый мем с подходящими подписью и комментариями.
Все посты и комментарии находятся в одной ленте. Участники могут оставлять комментарии.
Профиль содержит информацию текущего аккаунта; отдельный учебный аккаунт meme-reader имеет личную заметку с флагом.

Подписи и комментарии сохраняются на сервере и проходят через общий renderer HTML без экранирования.
Это одна причина Stored XSS в двух полях. Остальные пользовательские значения экранируются.
Сессии проверяются сервером, пароли хешируются salted scrypt.
Cookie kb2ctf_xss_session намеренно доступна JavaScript; это учебная настройка данной задачи.
Флаг provisioned локально и появляется только в профиле авторизованного аккаунта бота.

## Бот

Отдельный контейнер с Playwright 1.64.0 / Chromium.
Один browser context и одна вкладка; вся лента обновляется каждые 7 секунд.
Cookies сохраняются между обновлениями. После истечения двухчасовой сессии бот повторяет вход.
Навигация ограничена пятью секундами, посещения не перекрываются, диалоги закрываются.
Бот использует non-root UID 10001, Chromium sandbox, собственный shared memory и ограниченные ресурсы.
Hook может переподключаться при обновлении страницы; постоянное подключение не гарантируется.

## Запуск и reset

Из корня repository:

~~~sh
python tools/lab.py init
python tools/lab.py up xss
python tools/lab.py reset xss
~~~

Страница: http://127.0.0.1:8083.
Прямой запуск: docker compose -f tasks/xss/compose.yaml up -d --build --wait.
Остановка: python tools/lab.py down xss.
У задачи отдельный Compose project и named volume; reset не касается других заданий.
Reset удаляет accounts/posts/comments/sessions, меняет пароль бота и сохраняет flag.
Перезапуск приложения сохраняет данные и действующие сессии в volume.

## Ваш локальный hook-сервис

BeEF или аналог устанавливается и запускается владельцем стенда отдельно.
Переменная окружения XSS_HOOK_ORIGIN задаёт один разрешённый HTTP(S) origin без пути,
query, credentials и fragment. Она передаётся Compose при запуске задачи.
Укажите именно адрес, достижимый из Docker-контейнера; localhost внутри контейнера относится к нему самому.
На Docker Desktop предусмотрено имя host.docker.internal для подключения к host;
доступность конкретного Windows/WSL/VM сервиса зависит от его bind address и локальной сети.

Разрешены forum origin и настроенный hook origin, включая соответствующее WS/WSS соединение.
Если переменная пуста, внешние HTTP/WebSocket обращения браузера запрещены.
После изменения переменной пересоздайте сервис бота через повторный up xss.
Например, для сервиса на этом компьютере в PowerShell:

~~~powershell
$env:XSS_HOOK_ORIGIN = 'http://host.docker.internal:3000'
python tools/lab.py up xss
~~~

Настройка origin не загружает hook автоматически. В source, seed posts и assets нет встроенного hook.
Учебный флаг не выдаётся за событие подключения к hook-сервису.

## Проверки

Unit tests в tests/*.test.mjs проверяют auth, expiry, persisted benign HTML, concurrency и bot policy.
Для разработки нужны Node.js 24 и npm; установите зависимости отдельно в app/ и bot/ через npm ci --ignore-scripts.
Запуск из корня: node --test tasks/xss/tests/*.test.mjs.
Обычный Docker-запуск не требует Node.js/npm на host.
Integration checks входят в общий pytest suite: normal flow, restart, bot session/recovery и локальный HTTP/WebSocket fixture.
Они не сохраняют XSS payloads и не перехватывают браузерные сессии.
README, HINTS и FIX — единственные task-документы; WRITEUP.md не создаётся.
