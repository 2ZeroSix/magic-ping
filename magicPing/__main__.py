#!/usr/bin/sudo python3
import argparse
import logging
import os
import pathlib
import sys
from enum import Enum

from magicPing import client
from magicPing import server
from magicPing.icmp import monitor


class TypeOfApp(Enum):
    """
    Типы работы приложения
    """
    MONITOR = 0
    SERVER = 1
    CLIENT = 2


def get_parser() -> argparse.ArgumentParser:
    """
    генерация парсера аргументов командной строки
    :return: сгенерированный парсер
    """
    parser = argparse.ArgumentParser(
        description="Приложение для посылки/приёма сообщений с помощью ECHO REQUEST")
    parser.set_defaults(type=None)
    parser.add_argument("--log_file", "-l", dest="log_file", type=open,
                        default=sys.stderr, help="Путь до файла для логов")

    log_level = parser.add_mutually_exclusive_group()
    log_level.set_defaults(log_level=logging.INFO)
    log_level.add_argument("--error", "-e", dest="log_level",
                           action="store_const", const=logging.ERROR,
                           help="Ограничить логирование ошибками")
    log_level.add_argument("--info", "-i", dest="log_level",
                           action="store_const", const=logging.INFO,
                           help="Ограничить логирование информацией")
    log_level.add_argument("--debug", "-d", dest="log_level",
                           action="store_const", const=logging.DEBUG,
                           help="Ограничить логирование сообщениями для дебага")
    subparsers = parser.add_subparsers()

    server_parser = subparsers.add_parser("server", aliases=["s"], help="запуск сервера")
    server_parser.set_defaults(type=TypeOfApp.SERVER)
    server_parser.add_argument("--max_size", "-m", type=int, default=1024 ** 3 * 15,
                               help="Максимальный размер файла в байтах", )
    server_parser.add_argument("--thread_number", "-t", type=int, default=1,
                               help="Кол-во потоков, обрабатывающих пакеты")
    daemon_group = server_parser.add_mutually_exclusive_group()
    daemon_group.add_argument("--start_daemon", "-d", action="store_const",
                              const=True, default=False, help="Запустить в качестве демона")
    daemon_group.add_argument("--stop_daemon", "-s", action="store_const",
                              const=True, default=False, help="Завершить демона")
    daemon_group.add_argument("--restart_daemon", "-r", action="store_const",
                              const=True, default=False, help="Перезапустить демона")
    server_parser.add_argument("--target_path", "-p",
                               type=lambda x: pathlib.Path(os.path.realpath(x)),
                               default=pathlib.Path(os.getcwd()),
                               help="Директория для входящих файлов")

    client_parser = subparsers.add_parser("client", aliases=["c"], help="запуск клиента")
    client_parser.set_defaults(type=TypeOfApp.CLIENT)
    client_parser.add_argument("--max_size", "-m", type=int, default=1024 ** 3 * 15,
                               help="Максимальный размер файла в байтах")
    timeout_group = client_parser.add_mutually_exclusive_group()
    timeout_group.add_argument("--timeout", "-t", type=float, default=10.,
                               help="Максимальное время ожидания")
    timeout_group.add_argument("--unlimited", "-u", action="store_const",
                               const=None, dest="timeout", help="Не ограничивать время ожидания")
    client_parser.add_argument("--filename", "-f", default=None, help="Путь до файла для отправки")
    client_parser.add_argument("--destination", "-d", default=None, help="адрес получателя")
    client_parser.add_argument("--cypher", "-c", action="store_const",
                               const=True, default=False, help="Использовать шифрование")

    monitor_parser = subparsers.add_parser("monitor", aliases=["m"],
                                           help="запуск мониторинга " +
                                                "ping echo request/reply")
    monitor_parser.set_defaults(type=TypeOfApp.MONITOR)

    return parser


if __name__ == "__main__":
    parser = get_parser()
    args = parser.parse_args()
    logging.basicConfig(format="%(levelname)-8s [%(asctime)-15s; %(name)s]: %(message)s",
                        level=args.log_level, stream=args.log_file)

    if args.type == TypeOfApp.SERVER:
        if args.start_daemon:
            server.DaemonServer(args.max_size, args.thread_number, args.target_path).start()
        elif args.stop_daemon:
            server.DaemonServer(None, None, None).stop()
        elif args.restart_daemon:
            server.DaemonServer(None, None, None).restart()
        else:
            daemon_server = server.DaemonServer(args.max_size, args.thread_number, args.target_path,
                                                stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
            daemon_server.start()
            while input("введите \"q\", чтобы завершить работу сервера\n") != "q":
                pass
            else:
                daemon_server.stop()
                sys.exit(0)

    elif args.type == TypeOfApp.CLIENT:
        client = client.Client(max_size=args.max_size, timeout=args.timeout, enable_cypher=args.cypher)
        client.send(args.filename if args.filename is not None else input("Имя файла для отправки: "),
                    args.destination if args.destination is not None else input("Адресат: "))

    elif args.type == TypeOfApp.MONITOR:
        monitor()

    else:
        parser.print_help()
