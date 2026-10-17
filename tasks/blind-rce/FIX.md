# FIX — Blind Command Injection

Root cause совпадает с Pinger: пользовательский `ip` подставляется в строку
`ping %s -c 1`, которая передаётся в `subprocess.run(..., shell=True)`.
Shell интерпретирует метасимволы ввода как часть команды.

Как в оригинальном Pinger Deluxe Edition, `capture_output=True` захватывает оба потока,
но клиент получает только фиксированное сообщение: `bebebe error` при непустом stderr
или `bebebe pinged` в остальных случаях. Код возврата процесса не проверяется;
ненулевой exit code без stderr также приводит к `bebebe pinged`.
Сокрытие вывода не устраняет выполнение команд. `FLAG` передаётся через окружение,
поэтому доступна дочернему процессу. Дополнительных observer и marker нет.

Безопасный вариант:

~~~python
import ipaddress
import subprocess

def safe_diagnostic(host):
    address = str(ipaddress.ip_address(host))
    subprocess.run(
        ["/bin/ping", "-c", "1", "-W", "1", address],
        shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=3, check=False
    )
~~~

Сначала исправляется способ выполнения; политика отображения результата остаётся отдельным решением.
