# Attribution

Meme Forum — новая задача на JavaScript. Принцип авторизованного bot visit основан на:
https://github.com/FrakenboK/strict-dynamic-ctf-task/blob/4168d23da7e255386d7cc845cef5b31a2a4f79db/web/bot.py
Reference revision: 4168d23da7e255386d7cc845cef5b31a2a4f79db.
Git history, writeup, CSP/nonce chains и прочие приложения reference не перенесены.
Bot написан отдельно на JavaScript/Playwright. Семь локальных PNG-мемов предоставлены пользователем
для форума и перенесены без изменения изображений. Они заменяют первоначальный набор SVG.
Seccomp profile основан на microsoft/playwright v1.64.0 utils/docker/seccomp_profile.json,
с дополнительным разрешением chroot для Chromium namespace sandbox.
Лицензия исходного Playwright сохранена в bot/LICENSE.playwright (Apache-2.0).
