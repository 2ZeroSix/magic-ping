#!/usr/bin/sudo python3
import argparse
from enum import Enum

from magicPing import server
from magicPing import client
from magicPing.icmp import monitor


class TypeOfApp(Enum):
    MONITOR = 0
    SERVER = 1
    CLIENT = 2

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="send/receive messages through ECHO REQUEST")
    fullGroup = parser.add_mutually_exclusive_group()
    fullGroup.add_argument("--server", "-s", action="store_const",
                           const=TypeOfApp.SERVER, dest="type", help="run server")
    fullGroup.add_argument("--client", "-c", action="store_const",
                           const=TypeOfApp.CLIENT, dest="type", help="run client")
    fullGroup.add_argument("--monitor", "-m", action="store_const",
                           const=TypeOfApp.MONITOR, dest="type", help="run monitor")
    mtype = parser.parse_args().type
    if mtype == TypeOfApp.SERVER:
        server.Server(timeout=0).run()
    elif mtype == TypeOfApp.CLIENT:
        client.Client(timeout=0).send(input("Имя файла для отправки: "), input("Адресат: "))
    elif mtype == TypeOfApp.MONITOR:
        monitor()
    else:
        parser.print_help()
