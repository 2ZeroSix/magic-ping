# magic-ping
Приложение для посылки сообщений с помощью ICMP ECHO REQUEST

## Usage
запуск сервера с настройками по умолчанию:

сервер по умолчанию сохраняет входящие файлы в рабочую директорию
в формате: "время приёма:ip:icmp_id:имя файла"

```$ sudo python3 -m magicPing server```

для запуска сервера в режиме демона следует добавить флаг ```-d```

запуск клиента с настройками по умолчанию:

(запрашивает имя файла и адресата через стандартный ввод)

```$ sudo python3 -m magicPing client```

для использования шифрования следует добавить флаг -c

остальные аргументы описаны в соответствующих help'ах.

```$ python3 -m magicPing [client | server] -h```

###### Info
протестировано на ubuntu 16.04 LTS, версия python: 3.5.2

шифрование не стойкое,
в начале передачи данных происходит
обмен ключами по алгоритму Диффи-Хеллмана,
а затем на каждом шаге происходит xor данных с полученым ключом