# FIX — Blind Command Injection
Root cause совпадает с Pinger: command string передаётся shell. stdout/stderr направлены в DEVNULL,
но способ обработки input не изменился. Наличие marker демонстрирует только локальное предусмотренное состояние.

Backend создаёт случайный идентификатор попытки и отдельную область состояния.
LAB_MARKER_FILE сообщает диагностическому процессу предусмотренное место marker.
Observer не принимает путь от клиента, не предоставляет write endpoint, не раскрывает output или exit code.
Новая попытка не учитывает старое состояние. Observer просто проверяет наличие файла текущей попытки.
Добавленные input filters, timeout и process-group wrapper убраны.
Fixture в unit test устанавливает состояние напрямую и проверяет observer; это не execution scenario.

Безопасный вариант:
~~~python
import ipaddress
import subprocess

def safe_diagnostic(host):
    address = str(ipaddress.ip_address(host))
    subprocess.run(
        ["/usr/bin/ping", "-c", "1", "-W", "1", address],
        shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=3, check=False
    )
~~~

Сначала исправляется способ выполнения; политика отображения результата остаётся отдельным решением.
Marker и attempts хранятся в ограниченном tmpfs и очищаются при reset.
Нет interactive shell, callbacks или дополнительных сетевых компонентов.
