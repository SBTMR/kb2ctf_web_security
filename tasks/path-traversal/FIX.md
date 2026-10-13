# FIX — Path Traversal

Root cause: download соединяет user directory и filename без canonical containment.
Источник account id — signed session; исходный filesystem storage и burger.jpg сохраняются.
Upload повторяет исходную normpath/startswith проверку. Download отдаёт файл inline, как в оригинале.
В безопасном сервисе загрузки отдельно проверяют имя/размер, а скачивание отдаёт attachment с подходящим MIME policy.

Уязвимый участок:

~~~python
candidate = directory / filename
response = send_file(candidate)
~~~

Безопасный вариант для существующего файла:

~~~python
from pathlib import Path

def contained_file(base, name):
    if not isinstance(name, str) or not name or '\x00' in name or Path(name).is_absolute():
        raise ValueError('Invalid filename')
    trusted = Path(base).resolve(strict=True)
    candidate = (trusted / name).resolve(strict=True)
    if not candidate.is_relative_to(trusted) or not candidate.is_file():
        raise ValueError('File outside storage or unavailable')
    return candidate
~~~

resolve раскрывает canonical path, включая symlinks. Строковый startswith без directory boundary ненадёжен.
Для создания файла проверяйте existing parent и используйте простое имя/identifier.
Это пример для лабораторной Linux filesystem, не универсальная библиотека для всех ОС и concurrent storage.
Пароли учебной версии используют исходный SHA-256; безопасный вариант требует salted adaptive password hashing.
