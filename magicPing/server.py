import socket
import struct
import threading
import time

import logging

from magicPing import utils
from magicPing.icmp import receive_echo_request, send_echo_request
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class Server:
    class Context:
        def __init__(self, ip, icmp_id, flags, size):
            self.ip = ip
            self.icmp_id = icmp_id
            self.flags = flags
            self.size = size

    def __init__(self, max_size=1024**3 * 10, timeout=10):
        log.info("Инициализация сервера")
        log.debug("Максимальный размер файла: %s; таймаут(сек): %s",
                  max_size, timeout)
        self.max_size = max_size
        self.timeout = timeout
        self.exchangers = list()
        self.runnable = threading.Event()
        self.runnable.set()
        self.connects = dict()
        self.connects_lock = threading.Lock()

    def receive_magic_init(self):
        log.info("Ожидание инициализирующего сообщения")
        while self.runnable.is_set():
            ip, icmp_id, sequence_num, data = receive_echo_request(None, 0, 0)
            log.info("Получен эхо запрос")
            log.debug("ip:%s; id:%d; sequence number: %d",
                      ip, icmp_id, sequence_num)
            if len(data) == 19 and data[:10] == b'magic-ping':
                log.info("Получено инициализирующее сообщение")
                flags, size = struct.unpack("!BQ", data[10:19])
                return Server.Context(ip, icmp_id, flags, size)

    def receive_magic_data(self, ip, icmp_id, sequence_num):
        log.info("Получение куска файла")
        _, _, _, received_data = receive_echo_request(ip, icmp_id, sequence_num, self.timeout)
        send_echo_request(ip, icmp_id, sequence_num, bytes(utils.checksum(received_data)))
        return received_data

    def magic_exchange(self, context):
        ip = context.ip
        icmp_id = context.icmp_id
        flags = context.flags
        size = context.size
        log.info("Получение файла")
        log.debug("ip: %s; id: %d; flags: %s; size: %d.",
                  ip, icmp_id, bin(flags), size)
        try:
            with open("{}:{}:{}:{}".
                      format(ip, icmp_id, flags, size), "wb") as file:
                if size <= self.max_size:
                    if flags & 0x1:
                        pass    # TODO
                    else:
                        log.info("Обмен начался")
                        with self.connects_lock:
                            self.connects[ip] = icmp_id = self.connects.get(ip, -1) + 1
                        send_echo_request(ip, icmp_id, 0, b'magic-ping\x00')
                        sequence_num = 0
                        size = 0
                        while True:
                            data = self.receive_magic_data(ip, icmp_id,
                                                           sequence_num)
                            size += len(data)
                            if size > self.max_size:
                                log.warning("Превышен максимальный размер файла")
                                break
                            file.write(data)
                            sequence_num = (sequence_num + 1) % 65536
                else:
                    log.warning("Превышен максимальный размер файла")
                    send_echo_request(ip, icmp_id, 0, b'magic-ping\x01')
                    return 0x1
        except socket.timeout as _:
            log.warning("Превышено время ожидания клиента: ip: %s; icmp_id: %d", ip, icmp_id)

    def closer(self):
        while self.runnable.is_set():
            time.sleep(1)
            for exchanger in self.exchangers:
                exchanger.join(0.01)
                if not exchanger.is_alive():
                    self.exchangers.remove(exchanger)

    def run(self):
        log.info("Сервер запущен")
        closer = threading.Thread(target=self.closer)
        closer.start()
        while self.runnable.is_set():
            context = self.receive_magic_init()
            th = threading.Thread(target=self.magic_exchange, args=[context])
            th.start()
            self.exchangers.append(th)
        log.info("Сервер завершает работу")
        closer.join()
        log.info("Сервер завершил работу")
