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
        def __init__(self, ip, icmp_id, flags, size, filename):
            self.ip = ip
            self.icmp_id = icmp_id
            self.flags = flags
            self.size = size
            self.filename = filename

    def __init__(self, max_size=1024**3 * 10, timeout=10):
        log.info("Инициализация сервера")
        log.debug("Максимальный размер файла: %s; таймаут(сек): %s",
                  max_size, timeout)
        self.max_size = max_size
        self.timeout = timeout
        self.exchangers = list()
        self.exchangers_lock = threading.Lock()
        self.runnable = threading.Event()
        self.runnable.set()
        self.connects = dict()
        self.connects_lock = threading.Lock()

    def receive_magic_init(self):
        log.info("Ожидание инициализирующего сообщения")
        while self.runnable.is_set():
            try:
                ip, icmp_id, sequence_num, data = receive_echo_request(None, 0, 0, 1)
                log.info("Получен эхо запрос")
                log.debug("ip:%s; id:%d; sequence number: %d",
                          ip, icmp_id, sequence_num)
                if len(data) >= 19 and data[:10] == b'magic-ping':
                    log.info("Получено инициализирующее сообщение")
                    flags, size = struct.unpack("!BQ", data[10:19])
                    return Server.Context(ip, icmp_id, flags, size, data[19:])
            except socket.timeout:
                pass

    def receive_magic_data(self, ip, icmp_id, sequence_num):
        log.info("Получение куска файла")
        _, _, _, received_data = receive_echo_request(ip, icmp_id, sequence_num, self.timeout)
        send_echo_request(ip, icmp_id, sequence_num, struct.pack("!H", utils.checksum(received_data)))
        return received_data

    def magic_exchange(self, context):
        ip = context.ip
        icmp_id = context.icmp_id
        flags = context.flags
        log.info("Получение файла")
        log.debug("ip: %s; id: %d; flags: %s; size: %d.",
                  ip, icmp_id, bin(flags), context.size)
        try:
            if context.size <= self.max_size:
                if flags & 0x1:
                    pass    # TODO
                else:
                    log.info("Обмен начался")
                    with self.connects_lock:
                        self.connects[ip] = icmp_id = self.connects.get(ip, 0) + 1
                    with open("./" + context.filename, "wb") as file:
                        send_echo_request(ip, icmp_id, 0, b'magic-ping\x00' + context.filename)
                        sequence_num = 0
                        size = 0
                        while size < context.size:
                            data = self.receive_magic_data(ip, icmp_id,
                                                           sequence_num)
                            size += len(data)
                            if size > context.size:
                                log.warning("Превышен размер файла")
                                break
                            file.write(data)
                            sequence_num = (sequence_num + 1) % 65536
            else:
                log.warning("Превышен максимальный размер файла")
                send_echo_request(ip, icmp_id, 0, b'magic-ping\x01' + context.filename)
                return 0x1
        except socket.timeout as _:
            log.warning("Превышено время ожидания клиента: ip: %s; icmp_id: %d", ip, icmp_id)
        finally:
            with self.connects_lock:
                self.connects[ip] = self.connects.get(ip, 0) - 1
            log.info("Приём завершён: ip: %s; id: %s", ip, icmp_id)

    def closer(self):
        while self.runnable.is_set():
            time.sleep(1)
            with self.exchangers_lock:
                self.exchangers = [e for e in self.exchangers if e is None and not e.is_alive()]

    def run(self):
        log.info("Сервер запущен")
        closer = threading.Thread(target=self.closer)
        closer.start()
        local_exchangers = list()
        while self.runnable.is_set():
            context = self.receive_magic_init()
            if context is not None:
                th = threading.Thread(target=self.magic_exchange, args=[context])
                th.start()
                local_exchangers.append(th)
            if self.exchangers_lock.acquire(False):
                for elem in local_exchangers:
                    self.exchangers.append(elem)
                local_exchangers = list()
                self.exchangers_lock.release()
        closer.join()
        log.info("Сервер завершил работу")

    def stop(self):
        self.runnable.clear()
        log.info("Сервер завершает работу")
