# FIX — SSRF

Root cause: public Flask backend получает destination HTTP client из пользовательского URL без allowlist.
Internal Go Service имеет другие сетевые возможности, чем browser пользователя.
Отсутствие опубликованного порта и внутренний Authorization check не исправляют выбор destination gateway.
Учебный gateway повторяет исходный requests.get без added timeout, response cap и URL/header filters.
Requests defaults допускают redirects; безопасная версия требует явной destination policy.

Предпочтительно дать пользователю catalog server-owned sources и выбирать их по identifier.
Для controlled lab допустим строгий allowlist существующего sample-site:

~~~python
from urllib.parse import urlsplit

def allowed_source(raw):
    target = urlsplit(raw)
    if (target.scheme != 'http' or target.netloc != 'ssrf-sample:8080'
            or target.username or target.password):
        raise ValueError('Source not allowed')
    return raw
~~~

Проверка должна выполняться до HTTP request; client не следует redirects и не использует ambient proxy.
Не пересылайте произвольные credentials/headers к чувствительным destinations.
Дополнительная network policy ограничивает egress, internal service самостоятельно проверяет права.
Пример ограничен доверенным Docker DNS и controlled source. Произвольные интернет-источники требуют отдельной архитектуры.
Destination policy из FIX намеренно не включена в учебный gateway.
