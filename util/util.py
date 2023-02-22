def binstr(x: int, pad: int = 0):
    """
    Convert x into it's binary string and pad it with zeros on the left till len(x) >= pad is satisfied
    :param x: x
    :type x: int
    :param pad: zero-padding
    :type pad: int
    :return: A binary string padded with zeros as required
    :rtype: str
    """
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


def blockify(s: str, block_len: int) -> list[str]:
    """
    Slices s into a list of consecutive subarrays of length block_len. If len(s) % block_len != 0 the last element will not be padded.
    :param s: string to be sliced
    :type s: str
    :param block_len: length of the slice
    :type block_len: int
    :return: List containing the sliced strings
    :rtype: list[str]
    """
    return [s[i:i + block_len] for i in range(0, len(s), block_len)]