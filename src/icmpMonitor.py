#!/usr/bin/python3
import socket
import struct
from utility import ones_complement


def icmpmonitor():
    """
Monitoring ICMP messages
"""
    s = socket.socket(socket.AF_INET,
                      socket.SOCK_RAW,
                      socket.IPPROTO_ICMP)
    while True:
        msg = s.recv(65535)
        ipHeader = msg[:20]
        icmpHeader = msg[20:28]
        VerIHL, TypeOfService, TotalLength, Identification,\
            flags3FragmentOffset13, TimeToLive, Protocol,\
            ipHeaderChecksum, SrcAddr, DestAddr =\
            struct.unpack('!BBHHHBBH4s4s', ipHeader)
        data = struct.unpack('!' + str(TotalLength - 28) + 'c', msg[28:])
        flags = flags3FragmentOffset13 >> 13
        fragmentOffset = flags3FragmentOffset13 & 0x1FFFFF
        print("""
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         IP HEADER                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Ver:{:3}|IHL:{:3}|type of dev:{:3}|total length:{:6}            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|identification:{:6}          |flg{:2}|fragment offset:{:5}    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|time to live{:4}|protocol: {:4}|checksum:     {:5}            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|source                {:3}.{:3}.{:3}.{:3}                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|destination           {:3}.{:3}.{:3}.{:3}                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+""".
              format(VerIHL >> 4, VerIHL & 0xF,
                     TypeOfService, TotalLength,
                     Identification, flags,
                     fragmentOffset, TimeToLive,
                     Protocol, ipHeaderChecksum,
                     int(SrcAddr[0]), int(SrcAddr[1]),
                     int(SrcAddr[2]), int(SrcAddr[3]),
                     int(DestAddr[0]), int(DestAddr[1]),
                     int(DestAddr[2]), int(DestAddr[3])),
              end='')

        Type, Code, icmpChecksum, Identifier, SequenceNumber =\
            struct.unpack('!BBHHH', icmpHeader)
        print("""
|                        ICMP HEADER                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type:{:3}    |   Code:{:3}    |      Checksum:{:6}          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Identifier:{:6}        |    Sequence Number:{:5}      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+""".
              format(Type, Code, icmpChecksum, Identifier, SequenceNumber))
        icmp = [i
                for i in struct.unpack('!' + str((TotalLength - 20) // 2 + (TotalLength - 20) % 2) + 'H',
                                       msg[20:] + (b'\x00' if (TotalLength - 20) % 2 else b''))]
        icmp[1] = 0
        checksum = 0
        for elem in icmp:
            checksum = ones_complement(checksum + elem)
        print('checksum:{}'.format(65535 - checksum))
        print('DATA:', end=' ')
        for i in data:
            print(i, end=' ')
        print()
