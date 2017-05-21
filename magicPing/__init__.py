"""
                                   magic-ping
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
          A client/server app for data transfer within ping traffic
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
            ascii string            : 15 bytes  ==  "magic-ping-send"
            flags                   : 1 byte    ==  0x1 чтобы использовать шифрование
            size of message         : 8 bytes
            filename                : <= 65483  ==  Нуль-терминированная utf-8 строка
        ответ на инициализирующее сообщение:
            ascii string            : 15 bytes  == "magic-ping-recv"
            error code              : 1 byte    ==  0x1 если превышен максимальный размер
                                                        сообщения
            filename                : <= 65483  ==  Нуль-терминированная utf-8 строка
        обмен ключами шифрования на клиентской стороне:
            random value            : 8 bytes   >= 0
        обмене ключами шифрования на серверной стороне:
            random value            : 8 bytes   >= 0
        посылка данных:
            data                    : <= 65507 bytes
        ответ на посылку данных:
            checksum                : 16 битный обратный код
                                      дополняющей суммы всех
                                      16 байтных слов
                                      полученных данных
"""
# import logging

# logging.basicConfig(format="%(levelname)-8s [%(asctime)-15s; %(name)s]: %(message)s", level=logging.ERROR)
