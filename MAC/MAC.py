from PRF.PRF import PRF
from util.util import blockify, binstr


class MAC:

    """
    A variable length Message Authentication Code (MAC) generator and verifier
    that uses a pseudorandom function (PRF) and blockify function to split
    the input message into fixed-length blocks, and computes a tag by
    processing each block using the PRF with a unique index and a random
    identifier. The tag can be verified by computing a new tag using the
    same parameters, and comparing it with the received tag.
    """
    
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, seed: int) -> None:
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param seed: k
        :type seed: int
        """
        self.n, self.l = security_parameter, security_parameter // 4
        self.prf = PRF(security_parameter, generator, prime_field, seed)

    def mac(self, message: str, random_identifier: int) -> str:
        """
        Generate tag t
        :param random_identifier: r
        :type random_identifier: int
        :param message: message encoded as bit-string
        :type message: str
        :return: Returns the variable length MAC tag for given message and random id
        :rtype: str
        """
        blocks = blockify(message, self.l)
        blocks[-1] = blocks[-1].zfill(self.l)
        rs, ds = binstr(random_identifier, self.l), binstr(len(blocks), self.l)

        F_k = lambda i, m: self.prf.evaluate(int(rs + ds + i + m, 2))
        return rs + ''.join(
            binstr(F_k(binstr(i, self.l), b), self.n)
            for i, b in enumerate(blocks))

    def vrfy(self, message: str, tag: str) -> bool:
        """
        Verify whether the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: str
        :return: Verifies if tag received by running MAC on message matches given tag
        :rtype: bool
        """
        r = tag[:self.l]
        return self.mac(message, int(r, 2)) == tag