#!/usr/bin/sudo python3
import argparse
import threading
from enum import Enum

import logging

import sys

from magicPing import server
from magicPing import client
from magicPing.icmp import monitor


class TypeOfApp(Enum):
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
    parser.add_argument("--log_file", "-l", dest="log_file", type=open, default=sys.stdout)

    log_level = parser.add_mutually_exclusive_group()
    log_level.set_defaults(log_level=logging.ERROR)
    log_level.add_argument("--error", "-e", dest="log_level",
                           action="store_const", const=logging.ERROR)
    log_level.add_argument("--debug", "-d", dest="log_level",
                           action="store_const", const=logging.DEBUG)
    log_level.add_argument("--info", "-i", dest="log_level",
                           action="store_const", const=logging.INFO)

    subparsers = parser.add_subparsers()

    server_parser = subparsers.add_parser("server", aliases=["s"], help="запуск сервера")
    server_parser.set_defaults(type=TypeOfApp.SERVER)
    server_parser.add_argument("--max_size", "-m", type=int, default=1024 ** 3 * 10,
                               help="Максимальный размер файла")
    server_parser.set_defaults(log_level=logging.INFO)

    client_parser = subparsers.add_parser("client", aliases=["c"], help="запуск клиента")
    client_parser.set_defaults(type=TypeOfApp.CLIENT)
    client_parser.add_argument("--max_size", "-m", type=int, default=1024 ** 3 * 10)
    client_parser.add_argument("--timeout", "-t", type=float, default=10.)
    client_parser.add_argument("--filename", "-f", default=None)
    client_parser.add_argument("--destination", "-d", default=None)
    client_parser.set_defaults(log_level=logging.ERROR)

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
        server = server.Server(max_size=args.max_size)
        server_thread = threading.Thread(target=server.run)
        server_thread.start()
        while input("введите \"q\", чтобы завершить работу сервера: ") != "q":
            pass
        else:
            server.stop()
    elif args.type == TypeOfApp.CLIENT:
        client = client.Client(max_size=args.max_size, timeout=args.timeout)
        client.send(args.filename if args.filename is not None else input("Имя файла для отправки: "),
                    args.destination if args.destination is not None else input("Адресат: "))
    elif args.type == TypeOfApp.MONITOR:
        monitor()
    else:
        parser.print_help()
