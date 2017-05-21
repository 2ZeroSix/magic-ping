import logging
import socket
import struct
import os

import time

from pathlib import PurePath

from magicPing.icmp import receive_echo_request, send_echo_request
from magicPing import utils

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class Client():
    def __init__(self, max_size=1024**3 * 10, timeout=10):
        log.info("Инициализация клиента")
        log.debug("Максимальный размер файла: %s; таймаут: %s",
                  max_size, timeout)
        self.max_size = max_size
        self.timeout = timeout
        log.info("Инициализация клиента завершена")

    def send_magic_init(self, ip, filename, file_size):
        log.info("Посылка инициализирующего сообщения")
        try:
            bytes_filename = bytes(filename, "UTF-8")
            send_echo_request(ip, 0, 0, b'magic-ping\x00' + struct.pack("!Q", file_size) + bytes_filename)
            if self.timeout:
                start = time.time()
            sock_timeout = self.timeout
            while not self.timeout or sock_timeout > 0:
                _, icmp_id, _, data = receive_echo_request(ip, None, 0, sock_timeout)
                if len(data) >= 11 and data[:10] == b'magic-ping' and data[11:] == bytes_filename:
                    return icmp_id, data[10]
                elif self.timeout != 0:
                    sock_timeout = start - time.time() + self.timeout
            raise socket.timeout
        finally:
            log.info("Посылка инициализирующего сообщения завершена")

    def send_magic_data(self, ip, icmp_id, sequence_num, data):
        log.info("Посылка куска данных")
        try:
            checksum = utils.checksum(data)
            if self.timeout:
                start = time.time()
            sock_timeout = self.timeout
            while not self.timeout or sock_timeout > 0:
                send_echo_request(ip, icmp_id, sequence_num, data)
                _, _, _, data = receive_echo_request(ip, icmp_id, sequence_num,
                                                     sock_timeout / 2 if sock_timeout else 0.1)
                if checksum == struct.unpack("!H", data[:2]):
                    return
                elif self.timeout != 0:
                    sock_timeout = start - time.time() + self.timeout
            raise socket.timeout
        finally:
            log.info("Посылка куска данных завершена")

    def send(self, filename: str, dest: str):
        log.info("Посылка файла \"%s\"; назначение: %s", filename, dest)
        file = open(filename, "rb")
        file_size = os.stat(filename).st_size
        try:
            icmp_id, err = self.send_magic_init(dest, PurePath(filename).name, file_size)
            if err != 0:
                log.error("Сервер вернул ошибку: %d", err)
                return
            seq_num = 0
            while True:
                data = file.read(65507)
                if len(data) == 0:
                    break
                self.send_magic_data(dest, icmp_id, seq_num, bytes(data))
                seq_num = (seq_num + 1) % 65507
        except socket.timeout as _:
            log.error("Превышено время ожидания ответа от сервера: ip: %s", dest)
        log.info("Посылка файла завершена")
