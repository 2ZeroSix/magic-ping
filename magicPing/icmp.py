"""
    functions to work with ICMP
"""
import logging
import socket
import struct
import time

from magicPing import utils

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def monitor():
    """
    Monitoring ICMP messages
"""
    with socket.socket(socket.AF_INET,
                       socket.SOCK_RAW,
                       socket.IPPROTO_ICMP) as sock:
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
                         int(dst_address[2]), int(dst_address[3])), end='')

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


def receive_echo_request(source_address=None, preferred_id=None, preferred_seq_num=None, timeout=0):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW,
                       socket.IPPROTO_ICMP) as sock:
        if timeout is not None:
            start = time.time()
        sock_timeout = timeout
        while timeout is None or sock_timeout > 0:
            if sock_timeout is not None:
                sock.settimeout(sock_timeout)
            msg = memoryview(sock.recv(65535))
            ip = socket.inet_ntoa(msg[12:16])
            icmp_type, icmp_code, _, icmp_id, sequence_num\
                = struct.unpack("!BBHHH", msg[20:28])
            if not (icmp_type != 8 or icmp_code != 0):
                data = msg[28:]
                if (source_address is None or ip == source_address)\
                        or (preferred_id is None or icmp_id == preferred_id)\
                        or (preferred_seq_num is None or sequence_num == preferred_seq_num):
                    return ip, icmp_id, sequence_num, data
            if timeout is not None:
                sock_timeout = start - time.time() + timeout
        raise sock.timeout


def receive_echo_reply(source_address=None, preferred_id=None, preferred_seq_num=None, timeout=0):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW,
                       socket.IPPROTO_ICMP) as sock:
        if timeout is not None:
            start = time.time()
        sock_timeout = timeout
        while timeout is None or sock_timeout > 0:
            if sock_timeout is not None:
                sock.settimeout(sock_timeout)
            msg = memoryview(sock.recv(65535))
            ip = socket.inet_ntoa(msg[12:16])
            icmp_type, icmp_code, icmp_id, sequence_num\
                = struct.unpack("!BBHH", msg[20:28])
            if not (icmp_type != 0 or icmp_code != 0):
                data = msg[28:]
                if (source_address is None or ip == source_address)\
                        or (preferred_id is None or icmp_id == preferred_id)\
                        or (preferred_seq_num is None or sequence_num == preferred_seq_num):
                    return ip, icmp_id, sequence_num, data
            if timeout is not None:
                sock_timeout = start - time.time() + timeout
        raise sock.timeout
