# FIX — Command Injection
Root cause: backend собирает command string с пользовательским host и запускает shell.
Non-root и container resource limits не исправляют способ обработки input.
Флаг передаётся через переменную окружения `FLAG`, как в оригинале; запущенный shell наследует её.
Учебный обработчик использует исходный run без добавленного прикладного timeout.

Уязвимый участок:
~~~python
result = run(command, capture_output=True, shell=True, text=True)
~~~

Безопасная диагностика:
~~~python
import ipaddress
import subprocess

def safe_diagnostic(host):
    address = str(ipaddress.ip_address(host))
    return subprocess.run(
        ["/usr/bin/ping", "-c", "1", "-W", "1", address],
        shell=False, capture_output=True, text=True, timeout=3, check=False
    )
~~~

Executable выбирается сервером. Валидированный IP передаётся как один operand,
поэтому он не превращается в дополнительные options или shell syntax.
Не используйте shell escaping как замену этой конструкции для простой диагностики.
UI отображает результат через textContent; вывод процесса не становится HTML.
Прикладные timeout и очистка process group в исходном обработчике отсутствуют.
