# magic-ping
Приложение для посылки сообщений с помощью ICMP ECHO REQUEST

## Usage
запуск сервера с настройками по усмолчанию

```$ sudo python3 -m magicPing server```

запуск клиента с настройками по умолчанию
(запрашивает имя файла и адресата через стандартный ввод)

```$ sudo python3 -m magicPing client```

остальные аргументы описаны в соответствующих help'ах.

```$ python3 -m magicPing [client | server] -h```
