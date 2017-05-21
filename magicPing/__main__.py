#!/usr/bin/sudo python3
import argparse
import threading
from enum import Enum

from magicPing import server
from magicPing import client
from magicPing.icmp import monitor


class TypeOfApp(Enum):
    MONITOR = 0
    SERVER = 1
    CLIENT = 2


def get_parser():
    parser = argparse.ArgumentParser(
        description="Приложение для посылки/приёма сообщений с помощью ECHO REQUEST")
    parser.set_defaults(type=None)
    subparsers = parser.add_subparsers()

    server_parser = subparsers.add_parser("server", aliases=["s"],
                                          help="запуск сервера")
    server_parser.set_defaults(type=TypeOfApp.SERVER)
    server_parser.add_argument("--max_size", "-m", type=int, default=1024 ** 3 * 10,
                               help="Максимальный размер файла")
    server_parser.add_argument("--timeout", "-t", type=float, default=10.,
                               help="время ожидания ответа")

    client_parser = subparsers.add_parser("client", aliases=["c"],
                                          help="запуск клиента")
    client_parser.set_defaults(type=TypeOfApp.CLIENT)
    client_parser.add_argument("--max_size", "-m", type=int, default=1024 ** 3 * 10)
    client_parser.add_argument("--timeout", "-t", type=float, default=10.)
    client_parser.add_argument("--filename", "-f", default=None)
    client_parser.add_argument("--destination", "-d", default=None)

    monitor_parser = subparsers.add_parser("monitor", aliases=["m"],
                                           help="запуск мониторинга " +
                                                "ping echo request/reply")
    monitor_parser.set_defaults(type=TypeOfApp.MONITOR)

    return parser


if __name__ == "__main__":
    parser = get_parser()
    args = parser.parse_args()
    if args.type == TypeOfApp.SERVER:
        server = server.Server(max_size=args.max_size, timeout=args.timeout)
        server_thread = threading.Thread(target=server.run)
        server_thread.start()
        server_thread.ident
        while input() != "q":
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
