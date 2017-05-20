import logging
import socket
import struct
import os

import time

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

    def send_magic_init(self, ip, filesize):
        send_echo_request(ip, 0, 0, b'magic-ping\x00' + struct.pack("!Q", filesize))
        if self.timeout:
            start = time.time()
        sock_timeout = self.timeout
        while not self.timeout or sock_timeout > 0:
            _, icmp_id, _, data = receive_echo_request(ip, None, 0, sock_timeout)
            if len(data) == 11 and data[:10] == b'magic-ping':
                return icmp_id, data[10]
            elif self.timeout != 0:
                sock_timeout = start - time.time() + self.timeout
        raise socket.timeout

    def send_magic_data(self, ip, icmp_id, sequence_num, data):
        checksum = utils.checksum(data)
        if self.timeout:
            start = time.time()
        sock_timeout = self.timeout
        while not self.timeout or sock_timeout > 0:
            send_echo_request(ip, icmp_id, sequence_num, data)
            _, _, _, data = receive_echo_request(ip, icmp_id, sequence_num, sock_timeout)
            if checksum == struct.unpack("!H", data):
                return
            elif self.timeout != 0:
                sock_timeout = start - time.time() + self.timeout
        raise socket.timeout

    def send(self, filename: str, dest: str):
        file = open(filename, "rb")
        filesize = os.stat(filename).st_size
        try:
            icmp_id, err = self.send_magic_init(dest, filesize)
            if err != 0:
                log.error("Сервер вернул ошибку: %d", err)
                return
            data = file.read(65507)
            seq_num = 0
            while True:
                self.send_magic_data(dest, icmp_id, seq_num, bytes(data))
                seq_num = (seq_num + 1) % 65507
        except socket.timeout as _:
            log.error("Превышено время ожидания ответа от сервера: ip: %s", dest)
