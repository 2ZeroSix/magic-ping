import datetime
import logging
import socket
import struct
import threading
from pathlib import PurePath

from magicPing.icmp import send_echo_request

log = logging.getLogger(__name__)


class Server:
    class Packet(object):
        def __init__(self, ip, id, seq_num, data):
            """
            Информация о пакете
            :param ip: адрес отправителя
            :param id: идентификатор отправителя
            :param seq_num: номер пакета
            :param data: данные
            """
            self.ip = ip
            self.id = id
            self.seq_num = seq_num
            self.data = data

    class Context:
        def __init__(self, flags, size, filename):
            """
            Контекст соединения
            :param flags: флаги
            :param size: размер файла
            :param filename: имя файла
            """
            self.flags = flags
            self.size = size
            self.cur_size = 0
            self.filename = filename
            self.seq_num = 0
            self.key = 0
            self.lock = threading.Lock()
            self.start_time = datetime.datetime.now().isoformat()

        def __eq__(self, other):
            return (self.flags == other.flags
                    and self.size == other.size
                    and self.filename == other.filename)

        def __hash__(self):
            return hash(hash(self.flags) + hash(self.size) + hash(self.filename))

    def __init__(self, max_size=1024**3 * 10, thread_num=2):
        """
        Сервер получающий файлы с помощью ICMP ECHO REQUEST
        :param max_size: максимальный размер принимаемого файла
        """
        log.info("Инициализация сервера")
        log.debug("Максимальный размер файла: %s", max_size)
        self.tasks = set()
        self.tasks_count = threading.Semaphore(0)
        self.tasks_lock = threading.Lock()
        self.contexts = dict()
        self.contexts_lock = threading.Lock()
        self.max_size = max_size
        self.runnable = threading.Event()
        self.runnable.set()
        self.connects = dict()
        self.connects_lock = threading.Lock()
        self.thread_num = thread_num
        self.sock = None

    def run(self):
        """
        запуск сервера
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                self.sock = sock

                log.info("Сервер запущен")
                workers = [threading.Thread(target=self.worker) for _ in range(self.thread_num)]
                for worker in workers:
                    worker.start()
                self.listener()
                for _ in workers:
                    self.tasks_count.release()
                for worker in workers:
                    worker.join()
                log.info("Сервер завершил работу")
        finally:
            self.sock = None

    def stop(self):
        """
        остановка сервера
        """
        self.runnable.clear()
        log.info("Сервер завершает работу")

    def listener(self):
        """
        слушатель запросов
        """
        self.sock.settimeout(1)
        log.info("Сервер начал прослушивание запросов")
        while self.runnable.is_set():
            try:
                msg = memoryview(self.sock.recv(65535))
                ip = socket.inet_ntoa(msg[12:16])
                icmp_type, icmp_code, _, icmp_id, sequence_num \
                    = struct.unpack("!BBHHH", msg[20:28])
                if icmp_type == 8 and icmp_code == 0:
                    log.debug("Получен запрос: ip: %s; id: %d; seq_num: %d",
                              ip, icmp_id, sequence_num)
                    data = msg[28:]
                    if data[:10] == b'magic-ping':
                        with self.tasks_lock:
                            self.tasks.add(Server.Packet(ip, icmp_id, sequence_num, data))
                        self.tasks_count.release()
            except socket.timeout:
                pass
        log.info("Сервер закончил прослушивание запросов")

    def worker(self):
        """
        обработчик пакетов
        """
        log.debug("Запущен обработчик пакетов")
        while self.tasks_count.acquire() and self.runnable.is_set():
            with self.tasks_lock:
                task = self.tasks.pop()
            ip = task.ip
            id = task.id
            seq_num = task.seq_num
            data = task.data
            log.debug("Началась обработка пакета: ip: %s; id: %d; seq_num: %d", ip, id, seq_num)
            if id == 0 and seq_num == 0 and len(data) > 24 and data[:15] == b'magic-ping-sini':
                log.debug("Принят инициализирующий пакет: ip: %s; id: %s, filename:%s",
                          ip, id, str(data[24:], "UTF-8"))
                context = Server.Context(*struct.unpack("!BQ", data[15:24]), data[24:])
                with self.connects_lock:
                    self.connects[ip] = id = self.connects.get(ip, 0) + 1
                with self.contexts_lock:
                    if context in self.contexts.values():
                        log.info("Такое соединение уже установлено %s", context)
                        continue
                    self.contexts[ip + str(id)] = context
                err = 0
                if context.size > self.max_size:
                    err = 1
                send_echo_request(self.sock, ip, id, 0, b'magic-ping-rini'
                                  + struct.pack("!B", err) + context.filename)
                context.filename = PurePath(str(context.filename, "UTF-8")).name
                log.info("Начат приём файла: ip: %s; id: %d; filename: %s",
                         ip, id, context.filename)
                with open("{}:{}:{}:{}"
                          .format(context.start_time, ip, id, context.filename), "wb"):
                    pass
            elif len(data) > 16 and data[:15] == b'magic-ping-recv':
                log.debug("Получен пакет сервера (игнорируется): ip: %s; id: %d; seq_num: %d",
                          ip, id, seq_num)
                pass
            elif len(data) > 16 and data[:15] == b'magic-ping-send':
                with self.contexts_lock:
                    context = self.contexts.get(ip + str(id))
                    if context is None or context.seq_num < seq_num:
                        log.debug("Пакет неопознан: ip: %s; id: %d; seq_num: %d",
                                  ip, id, seq_num)
                        continue
                    elif context.seq_num > seq_num:
                        send_echo_request(self.sock, ip, id, seq_num, b'magic-ping-recv'+data[-2:-1])
                        continue
                    else:
                        if not context.lock.acquire(False):
                            continue
                if context.key is None and context.flags & 0x1:
                    pass  # TODO
                log.debug("Приём пакета: ip: %s; id: %d; seq_num: %d; filename: %s",
                          ip, id, seq_num, context.filename)
                with open("{}:{}:{}:{}"
                          .format(context.start_time, task.ip, task.id, context.filename), "ab") as file:
                    context.cur_size += len(data)
                    if context.cur_size > context.size:
                        log.error("Превышен размер файла")
                        with self.contexts_lock:
                            del self.contexts[ip + str(id)]
                        with self.connects_lock:
                            self.connects[ip] -= 1
                    send_echo_request(self.sock, ip, id, seq_num, b'magic-ping-recv'+data[-2:-1])
                    file.write(data)
                    if context.cur_size == context.size:
                        log.info("Завершён приём файла: ip: %s; id: %d; filename: %s",
                                 task.ip, task.id, context.filename)
                        with self.contexts_lock:
                            self.connects[ip] -= 1
                            del self.contexts[ip + str(id)]
                    context.seq_num = (context.seq_num + 1) % 65536
                log.debug("Приём пакета завершён: ip: %s; id: %d; seq_num: %d; filename: %s",
                          ip, id, seq_num, context.filename)
                context.lock.release()
        log.debug("Завершён обработчик запросов")
