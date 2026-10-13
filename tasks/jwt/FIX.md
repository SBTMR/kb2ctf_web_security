# FIX — JWT

Root cause: signing secret находится в распространяемом jwtutil.py.
Подпись HS256 проверяется, как в исходной задаче. Создаваемый token содержит только username, без exp.
Открытый ключевой материал разрушает предположение о том, кто может подписывать claims.
Название cookie, claim username и короткий опубликованный key сохранены из original task.
Учебный разбор сосредоточен на source review; подбор ключа не требуется.

Исправление: убрать secret из source, загрузить server-only provisioned key, заменить раскрытый ключ.
Источники доверенного key не должны зависеть от пользовательских claims.

~~~python
from pathlib import Path
import jwt

KEY = Path('/run/lab/jwt-key.txt').read_text(encoding='utf-8').strip()
payload = jwt.decode(token, KEY, algorithms=['HS256'],
                     options={'require': ['username', 'iat', 'exp']})
~~~

После validation отдельно проверяйте права пользователя. Для production добавьте expected issuer/audience
и подходящую политику срока действия/отзыва. Пароли следует хранить с salted adaptive hash,
а не в исходном виде, как это делает учебная in-memory регистрация. HttpOnly/SameSite cookies не исправляют раскрытый signing secret.
В локальном HTTP Secure cookie выключена; при HTTPS следует включить.
Reset очищает accounts; фиксированный учебный key остаётся в source.
