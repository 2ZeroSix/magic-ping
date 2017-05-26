import datetime
import logging
import socket
import struct
import threading
import itertools
import pathlib
import sys
import os
import time
import atexit
import signal

import math
import diffiehellman.diffiehellman

import magicPing.icmp

log = logging.getLogger(__name__)


class Server:
    """
    Сервер получающий файлы с помощью ICMP ECHO REQUEST
    файлы сохраняются в рабочую директорию в формате
    время приёма : ip : icmp_id : имя файла
    """

    class Packet(object):
        """
        Информация о пакете
        """

        def __init__(self, ip, id, seq_num, data):
            """
            :type ip: str
            :type id: int
            :type seq_num: int
            :type data: bytes или memoryview
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
        def __init__(self, ip, flags, size, filename):
            """
            Контекст соединения
            :type ip: str
            :type flags: int
            :type size: int
            :type filename: str
            :param ip: ip отправителя
            :param flags: флаги
            :param size: размер файла
            :param filename: имя файла
            """
            self.ip = ip
            self.flags = flags
            self.size = size
            self.received_size = 0
            self.filename = filename
            self.seq_num = 0
            self.private_key = None
            self.public_key = None
            self.lock = threading.Lock()
            self.start_time = datetime.datetime.now().isoformat()
            self.file = None

        def __eq__(self, other):
            """
            Сравнение контекстов на равенство ключевых свойств
            используется для отсеивания лишних инициализирующих пакетов
            :param other: контекст для сравнения
            :return: True, если равны, False иначе
            """
            return (self.ip == other.ip
                    and self.size == other.size
                    and self.filename == other.filename)

        def __str__(self):
            return self.ip + ":" + str(self.size) + ":" + self.filename

    def __init__(self, max_size=1024 ** 3 * 10, thread_num=2, target_path=pathlib.Path(os.getcwd())):
        """
        Инициализация сервера
        :type max_size: int
        :type thread_num: int
        :type target_path: pathlib.Path
        :param max_size: максимальный размер принимаемого файла
        :param thread_num: кол-во потоков осуществляющих приём данных
        :param target_path: директоория для входящих файлов
        """
        log.debug("Инициализация сервера: Максимальный размер файла: %d;" +
                  " кол-во потоков: %d; директория для входящих файлов: %s",
                  max_size, thread_num, target_path)
        self.tasks = set()
        self.tasks_count = threading.Semaphore(0)
        self.tasks_lock = threading.Lock()
        self.contexts = dict()
        self.contexts_lock = threading.Lock()
        self.max_size = max_size
        self.runnable = threading.Event()
        self.connects = dict()
        self.connects_lock = threading.Lock()
        self.thread_num = thread_num
        self.sock = None
        self.target_path = target_path
        os.makedirs(str(target_path), exist_ok=True)
        log.debug("Инициализация сервера завершена")

    def run(self):
        """
        запуск сервера
        """
        try:
            self.runnable.set()
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
                ip, icmp_id, sequence_num, data = \
                    magicPing.icmp.receive_echo_request(self.sock, timeout=1, prefix=b'magic-ping-s')
                if len(data) > 15 and data[:12] == b'magic-ping-s':
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
            try:
                with self.tasks_lock:
                    task = self.tasks.pop()
                ip = task.ip
                id = task.id
                seq_num = task.seq_num
                data = task.data
                log.debug("Началась обработка пакета: ip: %s; id: %d; seq_num: %d", ip, id, seq_num)
                if id == 0 and seq_num == 0 and len(data) > 24 and data[:15] == b'magic-ping-sini':
                    # инициализирующий пакет
                    bytes_filename = data[24:]
                    filename = pathlib.Path(str(bytes_filename, "UTF-8")).name
                    log.debug("Принят инициализирующий пакет: ip: %s; id: %s, filename:%s",
                              ip, id, filename)
                    context = Server.Context(ip, *struct.unpack("!BQ", data[15:24]), filename)
                    with self.connects_lock:
                        self.connects[ip] = id = self.connects.get(ip, 0) + 1
                    err = 0
                    if context.size > self.max_size:
                        log.info("Превышен максимальный размер файла")
                        err = 1
                    with self.contexts_lock:
                        if context in self.contexts.values():
                            log.info("Такое соединение уже установлено %s", context)
                            continue
                        self.contexts[ip + str(id)] = context
                    magicPing.icmp.send_echo_reply(self.sock, ip, id, 0, b'magic-ping-rini'
                                                   + struct.pack("!B", err) + bytes_filename)
                    if err:
                        continue
                    print(self.target_path)
                    print(self.target_path)
                    print(self.target_path / "{}:{}:{}:{}"
                          .format(context.start_time, context.ip, id, context.filename))
                    context.file = open(str(self.target_path / "{}:{}:{}:{}"
                                            .format(context.start_time, context.ip, id, context.filename)), "wb")
                    log.info("Начат приём файла: ip: %s; id: %d; filename: %s",
                             ip, id, context.filename)
                elif seq_num == 0 and data[:15] == b'magic-ping-skey':
                    # пакет обмена ключами
                    log.debug("Начат обмен ключами")
                    with self.contexts_lock:
                        context = self.contexts.get(ip + str(id))
                        if context is None or context.flags & 0x1 == 0:
                            log.debug("Пакет неопознан: ip: %s; id: %d; seq_num: %d",
                                      ip, id, seq_num)
                            continue
                        elif not context.lock.acquire(False):
                            continue
                    if context.private_key is None:
                        generator = diffiehellman.diffiehellman.DiffieHellman(key_length=1024)
                        generator.generate_public_key()
                        context.public_key = generator.public_key
                    magicPing.icmp \
                        .send_echo_reqply(self.sock, ip, id, 0, b'magic-ping-rkey' +
                                          generator.public_key.to_bytes(int(math.log2(context.public_key)) + 1,
                                                                        byteorder="big"))
                    if context.private_key is None:
                        generator.generate_shared_secret(int.from_bytes(data[15:], "big"))
                        context.private_key = bytearray.fromhex(generator.shared_key)
                    context.lock.release()
                    log.debug("Обмен ключами завершён")
                elif data[:15] == b'magic-ping-send':
                    # пакет с куском данных
                    with self.contexts_lock:
                        context = self.contexts.get(ip + str(id))
                        if context is None or context.seq_num < seq_num:
                            log.debug("Пакет неопознан: ip: %s; id: %d; seq_num: %d",
                                      ip, id, seq_num)
                            continue
                        elif context.seq_num == (seq_num + 1) % 65536:
                            magicPing.icmp.send_echo_reply(self.sock, ip, id, seq_num,
                                                           b'magic-ping-recv' + data[-1:])
                            continue
                        else:
                            if not context.lock.acquire(False):
                                continue
                    log.debug("Приём пакета: ip: %s; id: %d; seq_num: %d; filename: %s",
                              ip, id, seq_num, context.filename)
                    context.received_size += len(data) - 15
                    if context.received_size > context.size:
                        log.error("Превышен размер файла")
                        with self.contexts_lock:
                            del self.contexts[ip + str(id)]
                        with self.connects_lock:
                            self.connects[ip] -= 1
                    magicPing.icmp.send_echo_reply(self.sock, ip, id, seq_num,
                                                   b'magic-ping-recv' + data[-1:])
                    if context.private_key is None:
                        context.file.write(data[15:])
                    else:
                        context.file.write(bytes([a ^ b for a, b in zip(data[15:],
                                                                        itertools.cycle(context.private_key))]))
                    if context.received_size == context.size:
                        log.info("Завершён приём файла: ip: %s; id: %d; filename: %s",
                                 task.ip, task.id, context.filename)
                        context.file.close()
                        with self.contexts_lock:
                            self.connects[ip] -= 1
                            del self.contexts[ip + str(id)]
                    context.seq_num = (context.seq_num + 1) % 65536
                    context.lock.release()
                    log.debug("Приём пакета завершён: ip: %s; id: %d; seq_num: %d; filename: %s",
                              ip, id, seq_num, context.filename)
                else:
                    log.debug("Пакет неопознан: ip: %s; id: %d; seq_num: %d",
                              ip, id, seq_num)
            except Exception as _:
                log.exception("Неизвестная ошибка в обработчике пакетов")
                pass

        log.debug("Завершён обработчик запросов")


class DaemonServer:
    """
    Демон Сервера
    """
    def __init__(self, max_size, thread_num, target_path, pidfile='/tmp/magic-ping-daemon.pid',
                 stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        """
        Инициализация демона сервера
        :type max_size: int или None
        :type thread_num: int или None
        :type target_path: pathlib.Path или None
        :type pidfile: str
        :type stdin: str или sys.stdin
        :type stdout: str или sys.stdout
        :type stderr: str или sys.stderr
        :param max_size: максимальный размер принимаемого файла
        :param thread_num: кол-во потоков осуществляющих приём данных
        :param target_path: директоория для входящих файлов
        :param pidfile: pid файл для демона
        :param stdin: стандартный поток ввода демона
        :param stdout: стандартный поток вывода демона
        :param stderr: стандартный поток ошибок демона
        """
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.max_size = max_size
        self.thread_num = thread_num
        self.target_path = target_path
        self.server = None

    def daemonize(self):
        """
        Демонизация процесса
        :return: 1 из запустившего процесса, 0 из запущенного
        """
        try:
            pid = os.fork()
            if pid > 0:
                return 1
        except OSError:
            log.exception("fork #1 не удался")
            sys.exit(1)

        # отделяем от окружения родительского процесса
        os.chdir("/")
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError:
            log.exception("fork #2 не удался")
            sys.exit(1)
        # перенаправляем стандартные потоки
        sys.stdout.flush()
        sys.stderr.flush()
        if self.stdin != sys.stdin:
            si = open(self.stdin, 'r')
            os.dup2(si.fileno(), sys.stdin.fileno())
        if self.stdout != sys.stdout:
            so = open(self.stdout, 'a+')
            os.dup2(so.fileno(), sys.stdout.fileno())
        if self.stderr != sys.stderr:
            se = open(self.stderr, 'a+')
            os.dup2(se.fileno(), sys.stderr.fileno())

        # регистрируем удаление pid файла при завершении
        atexit.register(self.del_pid)
        # записываем свой pid файл
        pid = str(os.getpid())
        open(self.pidfile, 'w+').write(str(pid) + "\n")
        return 0

    def del_pid(self):
        """
        удаляет pid файл демона
        """
        os.remove(self.pidfile)

    def start(self):
        """
        Запуск демона
        """
        # проверка pid файла (если есть, то демон должно быть работает)
        try:
            pf = open(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if pid:
            log.error("pidfile {} уже существует. Демон уже работает?".format(self.pidfile))
            sys.exit(1)

        # стартуем демон
        if self.daemonize() == 1:
            return
        self.run()

    def stop(self):
        """
        Остановка демона
        """
        # получение pid процесса из своего pid файла
        try:
            pf = open(self.pidfile, 'r')
            pidstr = pf.read()
            pid = int(pidstr)
            pf.close()
        except IOError:
            pid = None

        if not pid:
            log.warning("pidfile %s does not exist. Daemon not running?", self.pidfile)
            return

        # пытаемся убить процесс
        try:
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(1)
        except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                log.exception("Unknown error")
                sys.exit(1)

    def restart(self):
        """
        Перезапуск демона
        """
        self.stop()
        self.start()

    def signal_terminating(self, _, __):
        self.server.stop()
        signal.signal(signal.SIGTERM, signal.SIG_DFL)

    def run(self):
        """
        цель демона
        """
        self.server = Server(self.max_size, self.thread_num, self.target_path)
        signal.signal(signal.SIGTERM, self.signal_terminating)
        self.server.run()
        exit(0)