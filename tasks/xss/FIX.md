# FIX — Stored XSS

Root cause: сервер принимает подписи и комментарии как данные, сохраняет их,
а общий EJS partial отображает их как доверенный HTML.
Эта ошибка пересекает trust boundary между автором поста и браузером читателя.
Бот является другим авторизованным читателем, а не механизмом выдачи флага за hook event.

Уязвимый renderer:

~~~ejs
<div class="saved-content"><%- content %></div>
~~~

Если продукту нужен обычный текст, выводите его с HTML escaping:

~~~ejs
<div class="saved-content"><%= content %></div>
~~~

Для сохранения переносов строк используйте CSS white-space: pre-wrap.
Для client-side обновлений обычного текста используйте textContent.
Если форматирование необходимо, применяйте поддерживаемый HTML sanitizer со строгим allowlist;
самодельный blacklist не заменяет безопасную обработку HTML.

Дополнительная защита сессии:

~~~javascript
res.cookie('kb2ctf_xss_session', token, {
  httpOnly: true,
  sameSite: 'strict',
  secure: true,
  path: '/',
  maxAge: 2 * 60 * 60 * 1000
});
~~~

Secure применяется при HTTPS; учебный стенд использует локальный HTTP.
HttpOnly препятствует чтению cookie из JavaScript, но не исправляет Stored XSS:
вредоносный код всё ещё может выполнять действия в браузере пользователя.
SameSite не является защитой от кода, уже выполняющегося в origin приложения.
Сервер продолжает проверять срок, владельца и права сессии, logout отзывает её.
Password hashing и sandbox браузера решают другие задачи и не устраняют unsafe HTML rendering.
