from PRF.PRF import PRF
from util.util import blockify


class CBC_MAC:

    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, keys: list[int]) -> None:
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: q
        :type prime_field: int
        :param keys: k₁, k₂
        :type keys: list[int]
        """
        self.n = security_parameter
        self.prfs = [PRF(self.n, generator, prime_field, k) for k in keys]

    def mac(self, message: str) -> int:
        """
        Message Authentication code for message
        :param message: message encoded as bit-string m
        :type message: str
        :return: Returns the MAC code for given message
        :rtype: int
        """
        t = 0
        f_1, f_2 = self.prfs
        for b in blockify(message, self.n):
            t = f_1.evaluate(t ^ int(b, 2))
        return f_2.evaluate(t)

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify if the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        :return: True if tag commits to message, else False
        :rtype: bool
        """
        return self.mac(message) == tag
