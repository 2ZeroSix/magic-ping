import logging
import socket
import struct
import os
import threading

import time

import math

from diffiehellman import diffiehellman
import pathlib

import itertools

from magicPing import icmp
from magicPing import utils

log = logging.getLogger(__name__)


class Client:
    """
    Клиент, отправляющий файлы с помощью ICMP ECHO REQUEST/REPLY
    """
    def __init__(self, max_size=1024**3 * 10, timeout=10., enable_cypher=False):
        """
        Инициализация клиента
        :type max_size: int
        :type timeout: float
        :type enable_cypher: bool
        :param max_size: максимальный размер файла
        :param timeout: максимальное время ожидаиния ответа
        :param enable_cypher: Использование шифрования
        """
        log.debug("Инициализация клиента")
        log.debug("Максимальный размер файла: %s; таймаут: %s",
                  max_size, timeout)
        self.max_size = max_size
        self.timeout = timeout
        self.enable_cypher = enable_cypher
        self.iteration = threading.Semaphore(0)
        self.runnable = threading.Event()
        self.runnable.set()
        self.sock = None
        self.key = None
        log.debug("Инициализация клиента завершена")

    def send_magic_init(self, ip, filename, file_size):
        """
        посылка инициализирующего сообщения
        :type ip: str
        :type filename: str
        :type file_size: int
        :param ip: ip адресата
        :param filename: имя файла
        :param file_size: размер файла
        :return: кортеж: (id сеанса передачи файла, код ошибки)
        """
        log.debug("Посылка инициализирующего сообщения")
        try:
            bytes_filename = bytes(filename, "UTF-8")
            if self.timeout is not None:
                start = time.time()
            sock_timeout = self.timeout
            while self.timeout is None or sock_timeout > 0:
                try:
                    flags = 1 if self.enable_cypher else 0
                    icmp.send_echo_request(self.sock, ip, 0, 0,
                                           b'magic-ping-sini' + struct.pack("!B", flags) +
                                           struct.pack("!Q", file_size) +
                                           bytes_filename)
                    _, icmp_id, _, data =\
                        icmp.receive_echo_reply(self.sock, ip, None, 0,
                                                sock_timeout / 2 if sock_timeout is not None else 1,
                                                b'magic-ping-rini', bytes_filename)
                    return icmp_id, data[15]
                except socket.timeout:
                    pass
                if self.timeout is not None:
                    sock_timeout = start - time.time() + self.timeout
            raise socket.timeout
        finally:
            log.debug("Посылка инициализирующего сообщения завершена")

    def create_cypher_key(self, ip, icmp_id):
        """
        создание ключа шифрования
        :type ip: str
        :type icmp_id: int
        :param ip: адресат 
        :param icmp_id: id сеанса передачи файла
        :return: общий ключ шифрования
        """
        log.debug("Начат обмен ключами")
        generator = diffiehellman.DiffieHellman(key_length=2048)
        generator.generate_public_key()
        if self.timeout is not None:
            start = time.time()
        sock_timeout = self.timeout
        while self.timeout is None or sock_timeout > 0:
            try:
                icmp.send_echo_request(self.sock, ip, icmp_id, 0,
                                       b'magic-ping-skey' +
                                       generator.public_key.to_bytes(int(math.log2(generator.public_key)) + 1,
                                                                     byteorder="big"))
                _, _, _, data = icmp.receive_echo_reply(self.sock, ip, icmp_id, 0,
                                                        sock_timeout / 2 if sock_timeout is not None else 1,
                                                        b'magic-ping-rkey')
                generator.generate_shared_secret(int.from_bytes(data[15:], "big"))
                return bytearray.fromhex(generator.shared_key)
            except socket.timeout:
                pass
            if self.timeout is not None:
                sock_timeout = start - time.time() + self.timeout
        log.debug("Обмен ключами завершён")
        raise socket.timeout

    def send_magic_data(self, ip, icmp_id, sequence_num, data):
        """
        Посылка куска сообщения
        :type ip: str
        :type icmp_id: int
        :type sequence_num: int
        :type data: bytes или memoryview
        :param ip: адресат
        :param icmp_id: id сеанса передачи файла
        :param sequence_num: номер куска сообщения
        :param data: данные для передачи
        :return: None
        """
        log.debug("Посылка куска данных")
        try:
            if self.timeout is not None:
                start = time.time()
            sock_timeout = self.timeout
            if self.enable_cypher:
                data = bytes([a ^ b for a, b in zip(data, itertools.cycle(self.key))])
            while self.timeout is None or sock_timeout > 0:
                try:
                    icmp.send_echo_request(self.sock, ip, icmp_id, sequence_num, b'magic-ping-send' + data)
                    _, _, _, data = \
                        icmp.receive_echo_reply(self.sock, ip, icmp_id, sequence_num,
                                                sock_timeout / 2 if sock_timeout is not None else 1,
                                                b'magic-ping-recv' + data[-1:])
                    return
                except socket.timeout:
                    pass
                if self.timeout is not None:
                    sock_timeout = start - time.time() + self.timeout
            raise socket.timeout
        finally:
            log.debug("Посылка куска данных завершена")

    def send(self, filename, dest, enable_cypher=None):
        """
        Посылка файла
        :type filename: str
        :type dest: str
        :type enable_cypher: bool
        :param filename: имя файла
        :param dest: адресат
        :param enable_cypher: использование шифрования (None == self.enable_cypher)
        :return: None
        """
        with socket.socket(socket.AF_INET, socket.SOCK_RAW,
                           socket.IPPROTO_ICMP) as sock:
            self.sock = sock
            log.info("Посылка файла \"%s\"; назначение: %s", filename, dest)
            file = open(filename, "rb")
            file_size = os.stat(filename).st_size
            try:
                icmp_id, err = self.send_magic_init(dest, pathlib.PurePath(filename).name, file_size)
                enable_cypher = enable_cypher if enable_cypher is not None else self.enable_cypher
                if err != 0:
                    log.error("Сервер вернул ошибку: %d", err)
                    return
                if enable_cypher:
                    self.key = self.create_cypher_key(dest, icmp_id)
                seq_num = 0
                total_iterations = file_size // 65492 + (1 if file_size % 65492 else 0)
                for i in range(total_iterations):
                    utils.print_progress_bar(i, total_iterations)
                    data = file.read(65492)
                    self.send_magic_data(dest, icmp_id, seq_num, data)
                    seq_num = (seq_num + 1) % 65536
                else:
                    utils.print_progress_bar(total_iterations, total_iterations)
            except socket.timeout:
                log.error("Превышено время ожидания ответа от сервера: ip: %s", dest)
            finally:
                log.info("Посылка файла завершена")
                self.sock = None
