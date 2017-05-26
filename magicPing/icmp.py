"""
Функции для работы с ICMP ECHO REPLY/REQUEST
"""
import logging
import socket
import struct
import time

log = logging.getLogger(__name__)


def monitor():
    """
    Мониторинг ICMP ECHO REPLY/REQUEST пакетов
    """
    with socket.socket(socket.AF_INET,
                       socket.SOCK_RAW,
                       socket.IPPROTO_ICMP) as sock:
        while True:
            msg = sock.recv(65535)  # 65535 is a max value of total length
            ip_header = msg[:20]
            icmp_header = msg[20:24]
            echo_header = msg[24:28]
            # noinspection SpellCheckingInspection
            ver_ihl, type_of_service, total_length, identification, \
                flags3_fragment_offset13, time_to_live, protocol, \
                ip_checksum, src_address, dst_address = \
                struct.unpack('!BBHHHBBH4s4s', ip_header)
            flags = flags3_fragment_offset13 >> 13
            fragment_offset = flags3_fragment_offset13 & 0x1FFF
            # noinspection SpellCheckingInspection
            print("""
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         IP HEADER                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Ver:{:3}|IHL:{:3}|typeof serv:{:3}|total length:{:6}            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|identification:{:6}          |flg{:2}|fragment offset:{:6}   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|time to live{:4}|protocol: {:4}|checksum:     {:6}           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|source                {:3}.{:3}.{:3}.{:3}                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|destination           {:3}.{:3}.{:3}.{:3}                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+""".
                  format(ver_ihl >> 4, ver_ihl & 0xF,
                         type_of_service, total_length,
                         identification, flags,
                         fragment_offset, time_to_live,
                         protocol, ip_checksum,
                         int(src_address[0]), int(src_address[1]),
                         int(src_address[2]), int(src_address[3]),
                         int(dst_address[0]), int(dst_address[1]),
                         int(dst_address[2]), int(dst_address[3])), end='')

            icmp_type, icmp_code, icmp_checksum = \
                struct.unpack('!BBH', icmp_header)
            print("""
|                        ICMP HEADER                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type:{:3}    |   Code:{:3}    |      Checksum:{:6}          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+""".
                  format(icmp_type, icmp_code, icmp_checksum), end='')
            if (icmp_type == 8 or icmp_type == 0) and icmp_code == 0:
                identifier, sequence_number = \
                    struct.unpack('!HH', echo_header)
                print("""
|                          ECHO HEADER                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Identifier:{:6}        |    Sequence Number:{:5}      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+""".
                      format(identifier, sequence_number))
                print('Description length: ', len(msg[28:]))


def send_echo_request(sock, ip, icmp_id, sequence_num, data):
    """
    Посылка ICMP ECHO REQUEST
    :param sock: сокет для отправки сообщения
    :param ip: адресат
    :param icmp_id: идентификатор
    :param sequence_num: номер сообщения
    :param data: данные
    """
    icmp_type = 8
    icmp_code = 0
    # noinspection SpellCheckingInspection
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code,
                              0, icmp_id, sequence_num)
    msg = icmp_header + data
    sock.sendto(msg, (ip, 0))


def send_echo_reply(sock, ip, icmp_id, sequence_num, data):
    """
    Посылка ICMP ECHO REPLY
    :param sock: сокет для отправки сообщения
    :param ip: адресат
    :param icmp_id: идентификатор
    :param sequence_num: номер сообщения
    :param data: данные
    """
    icmp_type = 0
    icmp_code = 0
    # noinspection SpellCheckingInspection
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code,
                              0, icmp_id, sequence_num)
    msg = icmp_header + data
    sock.sendto(msg, (ip, 0))


def receive_echo_request(sock, source_address=None, pref_id=None,
                         pref_seq_num=None, timeout=0,
                         prefix=None, suffix=None):
    """
    Получение ICMP ECHO REQUEST
    :param sock: сокет для приёма сообщения
    :param source_address: ожидаемый адрес отправителя
    :param pref_id: ожидаемый идетификатор отправителя
    :param pref_seq_num: ожидаемый номер сообщения
    :param timeout: время ожидания сообщения
    :param prefix: ожидаемое начало сообщения
    :param suffix: ожидаемый конец сообщения
    :return: кортеж информации о полученном сообщении
                (ip, icmp id, sequence number, data)
    """
    if timeout is not None:
        start = time.time()
    sock_timeout = timeout
    while timeout is None or sock_timeout > 0:
        try:
            if sock_timeout is not None:
                sock.settimeout(sock_timeout)
            msg = memoryview(sock.recv(65535))
            ip = socket.inet_ntoa(msg[12:16])
            icmp_type, icmp_code, checksum, icmp_id, seq_num\
                = struct.unpack("!BBHHH", msg[20:28].tobytes())
            if icmp_type == 8 or icmp_code == 0:
                data = msg[28:]
                if ((source_address is None
                     or socket.inet_aton(ip) == socket.inet_aton(socket.gethostbyname(source_address)))
                    and (pref_id is None or icmp_id == pref_id)
                    and (pref_seq_num is None or seq_num == pref_seq_num)
                    and (prefix is None or (len(data) >= len(prefix)
                                            and prefix == data[:len(prefix)]))
                    and (suffix is None or (len(data) >= len(suffix)
                                            and suffix == data[len(data) - len(suffix):]))):
                    return ip, icmp_id, seq_num, data
        except socket.timeout as _:
            pass
        if timeout is not None:
            sock_timeout = start - time.time() + timeout
    raise socket.timeout


def receive_echo_reply(sock, source_address=None, pref_id=None,
                       pref_seq_num=None, timeout=0,
                       prefix=None, suffix=None):
    """
    Получение ICMP ECHO REPLY
    :param sock: сокет для приёма сообщения
    :param source_address: ожидаемый адрес отправителя
    :param pref_id: ожидаемый идетификатор отправителя
    :param pref_seq_num: ожидаемый номер сообщения
    :param timeout: время ожидания сообщения
    :param prefix: ожидаемое начало сообщения
    :param suffix: ожидаемый конец сообщения
    :return: кортеж информации о полученном сообщении
                (ip, icmp id, sequence number, data)
    """
    if timeout is not None:
        start = time.time()
    sock_timeout = timeout
    while timeout is None or sock_timeout > 0:
        try:
            if sock_timeout is not None:
                sock.settimeout(sock_timeout)
            msg = memoryview(sock.recv(65535))
            ip = socket.inet_ntoa(msg[12:16])
            icmp_type, icmp_code, icmp_id, seq_num\
                = struct.unpack("!BBHH", msg[20:28].tobytes())
            if icmp_type == 0 and icmp_code == 0:
                data = msg[28:]
                if ((source_address is None or ip == source_address)
                    and (pref_id is None or icmp_id == pref_id)
                    and (pref_seq_num is None or seq_num == pref_seq_num)
                    and (prefix is None or (len(data) >= len(prefix)
                                            and prefix == data[:len(prefix)]))
                    and (suffix is None or (len(data) >= len(suffix)
                                            and suffix == data[len(data) - len(suffix):]))):
                    return ip, icmp_id, seq_num, data
        except socket.timeout as _:
            pass
        if timeout is not None:
            sock_timeout = start - time.time() + timeout

    raise socket.timeout
