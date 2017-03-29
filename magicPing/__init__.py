"""
                                   magic-ping
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
          A client/server app for data transfer within ping traffic
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
All communication is done through echo requests
Format of ICMP Echo Request:
    IP header       : 20 bytes
        Version             : 4 bits            ==  4
        IHL                 : 4 bits            ==  5
        Type of Service     : 1 byte            ==  0
        Total Length        : 2 bytes           >=  28
        Identification      : 2 bytes
        Flags               : 3 bits
        Fragment Offset     : 5 bits
        Time to Live        : 1 byte
        Protocol            : 1 byte            ==  1
        Header Checksum     : 2 bytes           ==  The 16 bit one's complement
                                                    of the one's complement
                                                    sum of all 16 bit words
                                                    in the header.
        Source Address      : 4 bytes
        Destination Address : 4 bytes
    ICMP            : up to 65515
        type                : 1 byte            ==  0
        code                : 1 byte            ==  0
        checksum            : 2 bytes           ==  The 16-bit ones's complement
                                                    of the one's complement sum
                                                    of the ICMP message
                                                    starting with the ICMP Type.
        ECHO part of header : 4 bytes
            identifier              : 2 bytes   ==  same for whole exchanging.
                                                    determined by identifier
                                                    of sender
            sequence number         : 2 bytes   ==  valid sequence number
                                                    on init == 0
                                                    (65535 followed by 0)
        Description         : up to 65507 bytes
        on init request:
            UTF-8 string            : 10 bytes  ==  "magic-ping"
            flags                   : 1 byte    ==  0x1 on using cypher
                                                    0x2, ..., 0x32 - reserved
            size of message         : 8 bytes
        on init reply:
            error code              : 1 byte    ==  0 on success
                                                    0x1 if message is too big
        on key exchanging request:
            TODO
        on key exchanging reply:
            TODO
        on data sending request:
            data                    : up to 65507 bytes
        on data sending reply:
            None (client should checking original echo replies from server)
"""

# import magicPing.icmp
# import magicPing.utils
