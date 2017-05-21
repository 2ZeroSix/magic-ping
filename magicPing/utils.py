from shutil import get_terminal_size


def carry_around_add(a, b):
    """
    дополняющая сумма
    :param a: первое слагаемое
    :param b: второе слагаемое
    :return: дополняющая сумма a и b
    """
    c = a + b
    return (c & 0xFFFF) + (c >> 16)


def checksum(msg, avoid_range=range(0)):
    """
    обратный код 16 битной дополняющей суммы елементов msg
    :param msg:
    :param avoid_range:
    :return:
    """
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


def print_progress_bar(iteration: int, total: int, prefix: str = '', suffix: str = '',
                       decimals: int = 1, length: int = None, fill: str = '█') -> None:
    """
        Call in a loop to create terminal progress bar
        :param iteration: current iteration
        :param total: total iterations
        :param prefix: prefix string
        :param suffix: suffix string
        :param decimals: positive number of decimals in percent complete
        :param length: character length of bar
        :param fill: bar fill character
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    if length is None:
        length = max(get_terminal_size()[0] - len(prefix) - len(suffix) - len(percent) - 5, 10)
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print('\r%s|%s| %s%% %s' % (prefix, bar, percent, suffix), end='\r')
    if iteration == total:
        print()
