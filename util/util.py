def binstr(x: int, pad: int = 0):
    return format(x, f'0{pad}b')


def xor(x: str, y: str) -> str:
    """
    XOR two bit strings of equal length
    :param a: first bit string
    :type a: str
    :param b: second bit string
    :type b: str
    :return: XOR result as a bit string
    :rtype: str
    """
    return binstr(int(x, 2) ^ int(y, 2), max(len(x), len(y)))