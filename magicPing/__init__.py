"""
                                   magic-ping
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
          Приложение для посылки сообщений с помощью ICMP ECHO REQUEST
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Все коммуникации происходят с помощью ICMP ECHO REQUEST
Формат ICMP Echo Request:
    IP header       : 20 bytes
        Version             : 4 bits            ==  4
        IHL                 : 4 bits            ==  5
        Type of Service     : 1 byte            ==  0
        Total Length        : 2 bytes           >=  28
        Identification      : 2 bytes
        Flags               : 3 bits
        Fragment Offset     : 5 bits
        Time to Live        : 1 byte
        Protocol            : 1 byte            ==  1
        Header Checksum     : 2 bytes           ==  16 битный обратный код
                                                    дополняющей суммы всех
                                                    16 байтных слов
                                                    в заголовке.
        Source Address      : 4 bytes
        Destination Address : 4 bytes
    ICMP            : up to 65515
        type                : 1 byte            ==  8
        code                : 1 byte            ==  0
        checksum            : 2 bytes           ==  16 битный обратный код
                                                    дополняющей суммы всех
                                                    16 байтных слов
                                                    начиная с поля type.
        ECHO part of header : 4 bytes
            identifier              : 2 bytes   ==  id сессии
                                                    1. при инициализации
                                                    на стороне клиента
                                                    == 0
                                                    2. сервер определяет
                                                    значение при инициализации
            sequence number         : 2 bytes   ==  при инициализации == 0
                                                    при обмене начиается с нуля
                                                    и увеличивается на 1
                                                    на каждом шаге
        Description         : <= 65507 bytes
        инициализирующее сообщение:
            ascii string            : 15 bytes  ==  "magic-ping-sini"
            flags                   : 1 byte    ==  0x1 чтобы использовать шифрование
            size of message         : 8 bytes
            filename                : <= 65483  ==  Нуль-терминированная utf-8 строка
        ответ на инициализирующее сообщение:
            ascii string            : 15 bytes  == "magic-ping-rini"
            error code              : 1 byte    ==  0x1 если превышен максимальный размер
                                                        сообщения
            filename                : <= 65483  ==  Нуль-терминированная utf-8 строка
        обмен ключами шифрования на клиентской стороне:
            ascii string            : 15 bytes  == "magic-ping-skey"
            random value            : 8 bytes   >= 0
        обмене ключами шифрования на серверной стороне:
            ascii string            : 15 bytes  == "magic-ping-rkey"
            random value            : 8 bytes   >= 0
        посылка данных:
            ascii string            : 15 bytes  == "magic-ping-send"
            data                    : <= 65492 bytes
        ответ на посылку данных:
            ascii string            : 15 bytes  == "magic-ping-recv"
            last_byte               : последний байт переданных данных
"""
import magicPing.client
import magicPing.server
import magicPing.icmp
import magicPing.utils
