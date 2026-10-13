# FIX — SQL Injection

Root cause: исходные queries вставляют пользовательские значения в SQL string.
SQLAlchemy text() сам по себе не делает interpolated string безопасной.
В этой редакции исходная логика регистрации, входа и notes перенесена без parameterization.

Исправление: использовать bound parameters для каждого query, отдельно проверять password hash.

~~~python
from sqlalchemy import text
from werkzeug.security import check_password_hash

with engine.begin() as connection:
    row = connection.execute(text(
        'SELECT id,username,password FROM users WHERE username=:name'
    ), {'name': username}).mappings().first()
authenticated = row is not None and check_password_hash(row['password'], password)
~~~

Этот безопасный пример предполагает переход хранилища паролей на salted adaptive hashes.
Исходный SHA-256 без соли не подходит для password storage; переход требует обновления hashes.
Password hashing и parameterization решают разные проблемы.
Ограничивайте DB privileges потребностями приложения и возвращайте понятные ошибки без database details.
