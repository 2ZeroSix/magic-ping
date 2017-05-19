"""
    functions to work with ICMP
"""
import logging
import socket
import struct
import threading
import time

from magicPing import utils


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def monitor():
    """
    Monitoring ICMP messages
"""
    sock = socket.socket(socket.AF_INET,
                         socket.SOCK_RAW,
                         socket.IPPROTO_ICMP)
    while True:
        msg = memoryview(sock.recv(65535))  # 65535 is a max value of total length
        ip_header = msg[:20]
        icmp_header = msg[20:24]
        echo_header = msg[24:28]
        # noinspection SpellCheckingInspection
        ver_ihl, type_of_service, total_length, identification, \
            flags3_fragment_offset13, time_to_live, protocol, \
            ip_checksum, src_address, dst_address = \
            struct.unpack('!BBHHHBBH4s4s', ip_header)
        flags = flags3_fragment_offset13 >> 13
        fragment_offset = flags3_fragment_offset13 & 0x1FFF
        # noinspection SpellCheckingInspection
        print("""
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         IP HEADER                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Ver:{:3}|IHL:{:3}|typeof serv:{:3}|total length:{:6}            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|identification:{:6}          |flg{:2}|fragment offset:{:6}   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|time to live{:4}|protocol: {:4}|checksum:     {:6}           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|source                {:3}.{:3}.{:3}.{:3}                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|destination           {:3}.{:3}.{:3}.{:3}                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+""".
              format(ver_ihl >> 4, ver_ihl & 0xF,
                     type_of_service, total_length,
                     identification, flags,
                     fragment_offset, time_to_live,
                     protocol, ip_checksum,
                     int(src_address[0]), int(src_address[1]),
                     int(src_address[2]), int(src_address[3]),
                     int(dst_address[0]), int(dst_address[1]),
                     int(dst_address[2]), int(dst_address[3])),
              end='')

        icmp_type, icmp_code, icmp_checksum = \
            struct.unpack('!BBH', icmp_header)
        print("""
|                        ICMP HEADER                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type:{:3}    |   Code:{:3}    |      Checksum:{:6}          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+""".
              format(icmp_type, icmp_code, icmp_checksum), end='')
        if (icmp_type == 8 or icmp_type == 0) and icmp_code == 0:
            identifier, sequence_number = \
                struct.unpack('!HH', echo_header)
            print("""
|                          ECHO HEADER                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Identifier:{:6}        |    Sequence Number:{:5}      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+""".
                  format(identifier, sequence_number))
            print('Description:', end=' ')
            for i in msg[28:]:
                print(i, end=' ')
        print()


def send_echo_request(ip, icmp_id, sequence_num, data):
    icmp_type = 8
    icmp_code = 0
    # noinspection SpellCheckingInspection
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code,
                              0, icmp_id, sequence_num)
    checksum = utils.carry_around_add(utils.checksum(icmp_header),
                                      utils.checksum(data))
    # noinspection SpellCheckingInspection
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code,
                              checksum, icmp_id, sequence_num)
    msg = icmp_header + data
    with socket.socket(socket.AF_INET, socket.SOCK_RAW,
                       socket.IPPROTO_ICMP) as sock:
        sock.connect((ip, 0))
        sock.send(msg)


def send_echo_reply(ip, icmp_id, sequence_num, data):
    icmp_type = 0
    icmp_code = 0
    # noinspection SpellCheckingInspection
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code,
                              0, icmp_id, sequence_num)
    checksum = utils.carry_around_add(utils.checksum(icmp_header),
                                      utils.checksum(data))
    # noinspection SpellCheckingInspection
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code,
                              checksum, icmp_id, sequence_num)
    msg = icmp_header + data
    with socket.socket(socket.AF_INET, socket.SOCK_RAW,
                       socket.IPPROTO_ICMP) as sock:
        sock.connect((ip, 0))
        sock.send(msg)


def receive_echo_request(source_address=None, timeout=0):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW,
                       socket.IPPROTO_ICMP) as sock:
        if timeout:
            sock.settimeout(timeout)
        while True:
            msg = memoryview(sock.recv(65535))
            ip = socket.inet_ntoa(msg[12:16])
            icmp_type, icmp_code, icmp_id, sequence_num = struct.unpack("!BBHH", msg[20:28])
            if icmp_type != 8 or icmp_code != 0:
                continue
            data = msg[28:]
            if source_address is None or ip == source_address:
                return ip, icmp_id, sequence_num, data

def receive_echo_reply(source_address=None, timeout=0):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW,
                       socket.IPPROTO_ICMP) as sock:
        if timeout:
            sock.settimeout(timeout)
        while True:
            msg = memoryview(sock.recv(65535))
            ip = socket.inet_ntoa(msg[12:16])
            icmp_type, icmp_code, icmp_id, sequence_num = struct.unpack("!BBHH", msg[20:28])
            if icmp_type != 0 or icmp_code != 0:
                continue
            data = msg[28:]
            if source_address is None or ip == source_address:
                return ip, icmp_id, sequence_num, data


class Server:
    def __init__(self, max_size=1024**3 * 10, timeout=10):
        log.info("init server")
        log.debug(" max_size:%s; timeout:%s",
                  max_size, timeout)
        self.max_size = max_size
        self.timeout = timeout
        self.exchangers = list()
        self.runnable = threading.Event()
        self.runnable.set()

    def receive_magic_init(self):
        log.info("monitor for magic-ping init messages")
        while self.runnable.is_set():
            ip, icmp_id, sequence_num, data = receive_echo_request()
            log.info("received echo request")
            log.debug("ip:%s; id:%d; sequence number:%d",
                      ip, icmp_id, sequence_num)
            if sequence_num == 0 and data[:10] == bytes("magic-ping", "ascii"):
                flags, size = struct.unpack("!BH", data[10:19])
                return ip, icmp_id, flags, size

    @staticmethod
    def receive_magic_data(ip, icmp_id, sequence_num):
        received_ip, received_icmp_id, \
            received_sequence_num, received_data = receive_echo_request()
        if received_ip == ip and \
            received_icmp_id == icmp_id and \
                received_sequence_num == sequence_num:
            return received_data

    def magic_exchange(self, context):
        ip, icmp_id, flags, size, _ = context
        log.info("Receiving file")
        log.debug("time: %s;ip: %s; id: %d; flags: %s; size: %d.",
                  time.localtime(), ip, icmp_id, bin(flags), size)
        with open("{}:{}:{}:{}".
                  format(ip, icmp_id, flags, size), "w") as file:
            if size <= self.max_size:
                if flags & 0x1:
                    pass    # TODO
                else:
                    send_echo_request(ip, icmp_id, 0, b'\x00')
                    sequence_num = 0
                    while True:
                        data = self.receive_magic_data(ip, icmp_id,
                                                       sequence_num)
                        if 0 < len(data) < 65507:
                            file.write(data)
                        else:
                            break
                        while True:
                            checksum = utils.checksum(data)
                            send_echo_request(ip, icmp_id, sequence_num, struct.pack("!H", checksum))
                            data = self.receive_magic_data(ip, icmp_id, sequence_num)
                            if struct.unpack("!H", data) == checksum:
                                break
                        sequence_num = (sequence_num + 1) % 65536
            else:
                send_echo_request(ip, icmp_id, 0, b'\x01')
                return 0x1

    def closer(self):
        while self.runnable.is_set() or len(self.exchangers) > 0:
            for exchanger in self.exchangers:
                exchanger.join(0.01)
                if not exchanger.is_alive():
                    self.exchangers.remove(exchanger)

    def run(self):
        log.info("running server")
        closer = threading.Thread(target=self.closer)
        closer.start()
        while self.runnable.is_set():
            context = self.receive_magic_init()
            th = threading.Thread(target=self.magic_exchange, args=context)
            th.start()
            self.exchangers.append(th)
        closer.join()

    def send_magic_data(self, ip, icmp_id, sequence_num):
        pass


class Client:
    def __init__(self, max_size=1024**3 * 10, timeout=10):
        log.info("init client")
        log.debug(" max_size:%s; timeout:%s",
                  max_size, timeout)
        self.max_size = max_size
        self.timeout = timeout

    def send():