def carry_around_add(a, b):
    c = a + b
    return (c & 0xFFFF) + (c >> 16)


def checksum(msg, avoid_range=range(0)):
    s = 0
    for i in range(1, len(msg), 2):
        a, b = 0, 0
        if i - 1 not in avoid_range:
            a = int(msg[i])
        if i not in avoid_range:
            b = int(msg[i - 1])
        w = a | (b << 8)
        s = carry_around_add(s, w)
    if len(msg) % 2 == 1:
        w = 0
        if len(msg) - 1 not in avoid_range:
            w = int(msg[len(msg) - 1]) << 8
        s = carry_around_add(s, w)
    return ~s & 0xFFFF
