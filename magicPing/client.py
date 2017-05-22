import logging
import random
import socket
import struct
import os

import time

from pathlib import PurePath

from magicPing.icmp import receive_echo_request, send_echo_request
from magicPing import utils

log = logging.getLogger(__name__)


class Client:
    def __init__(self, max_size=1024**3 * 10, timeout=10., enable_cypher=False):
        log.info("Инициализация клиента")
        log.debug("Максимальный размер файла: %s; таймаут: %s",
                  max_size, timeout)
        self.max_size = max_size
        self.timeout = timeout
        self.enable_cypher = enable_cypher
        log.info("Инициализация клиента завершена")

    def send_magic_init(self, ip, filename, file_size):
        log.debug("Посылка инициализирующего сообщения")
        try:
            bytes_filename = bytes(filename, "UTF-8")
            if self.timeout:
                start = time.time()
            sock_timeout = self.timeout
            while not self.timeout or sock_timeout > 0:
                try:
                    send_echo_request(ip, 0, 0,
                                      b'magic-ping-send\x00'
                                      + struct.pack("!Q", file_size)
                                      + bytes_filename)
                    _, icmp_id, _, data = receive_echo_request(ip, None, 0, sock_timeout,
                                                               b'magic-ping-recv')
                    if len(data) > 16 and data[16:] == bytes_filename:
                        return icmp_id, data[15]
                    elif self.timeout != 0:
                        sock_timeout = start - time.time() + self.timeout
                except socket.timeout:
                    pass
            raise socket.timeout
        finally:
            log.debug("Посылка инициализирующего сообщения завершена")

    def create_cypher_key(self, ip, icmp_id):
        send_echo_request(ip, icmp_id, 0,
                          b'magic-ping-skey' + struct.pack("!L", random.randrange(2**64)))
        # TODO

    def send_magic_data(self, ip, icmp_id, sequence_num, data):
        log.debug("Посылка куска данных")
        try:
            checksum = utils.checksum(data)
            if self.timeout:
                start = time.time()
            sock_timeout = self.timeout
            while not self.timeout or sock_timeout > 0:
                try:
                    send_echo_request(ip, icmp_id, sequence_num, data)
                    _, _, _, data =\
                        receive_echo_request(ip, icmp_id, sequence_num,
                                             sock_timeout / 2 if sock_timeout is not None else 0.1,
                                             struct.pack("!H", checksum))
                    return
                except socket.timeout:
                    pass
                if self.timeout != 0:
                    sock_timeout = start - time.time() + self.timeout
            raise socket.timeout
        finally:
            log.debug("Посылка куска данных завершена")

    def send(self, filename: str, dest: str, enable_cypher=None):
        log.info("Посылка файла \"%s\"; назначение: %s", filename, dest)
        file = open(filename, "rb")
        file_size = os.stat(filename).st_size
        try:
            icmp_id, err = self.send_magic_init(dest, PurePath(filename).name, file_size)
            enable_cypher = enable_cypher if enable_cypher is not None else self.enable_cypher
            if enable_cypher:
                key = self.create_cypher_key()
            if err != 0:
                log.error("Сервер вернул ошибку: %d", err)
                return
            seq_num = 0
            iterations = file_size // 65507 + (1 if file_size % 65507 else 0)
            for i in range(iterations):
                utils.print_progress_bar(i, iterations)
                data = file.read(65507)
                self.send_magic_data(dest, icmp_id, seq_num, bytes(data))
                seq_num = (seq_num + 1) % 65507
            utils.print_progress_bar(iterations, iterations)
        except socket.timeout:
            log.error("Превышено время ожидания ответа от сервера: ip: %s", dest)
        log.info("Посылка файла завершена")

