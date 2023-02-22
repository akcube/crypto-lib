from PRF.PRF import PRF
from util.util import xor, binstr, blockify


class CPA:

    def __init__(self,
                 security_parameter: int,
                 prime_field: int,
                 generator: int,
                 key: int,
                 mode="CTR") -> None:
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key: k
        :type key: int
        :param mode: Block-Cipher mode of operation
            - CTR
            - OFB
            - CBC
        :type mode: str
        """
        if (mode not in ['CTR', 'OFB', 'CBC']):
            raise ValueError(f"Unsupported mode: {self.mode}")
        self.n = security_parameter
        self.prf = PRF(security_parameter, generator, prime_field, key)
        self.mode = mode

        f = lambda rs: binstr(self.prf.evaluate(rs), self.n)
        self.ops = {
            'CTR': lambda b, rs: (xor(b, f(rs + 1)), rs + 1),
            'OFB': lambda b, rs: (xor(b, f(rs)), int(f(rs), 2)),
            'CBC': lambda b, rs:
            (xor(f(int(b, 2) ^ rs), b), int(f(int(b, 2) ^ rs), 2))
        }

    def crypt(self, message: str, random_seed: int) -> str:
        """
        Applies the appropriate encryption operation to the message string
        :param message: m
        :type message: int
        :param random_seed: r
        :type random_seed: int
        :return: Applies correct encryption operation to message string
        :rtype: str
        """
        cipher, op = "", self.ops[self.mode]
        for b in blockify(message, self.n):
            cipher_block, random_seed = op(b, random_seed)
            cipher += cipher_block
        return cipher

    def enc(self, message: str, random_seed: int) -> str:
        """
        Encrypt message against Chosen Plaintext Attack via initialized mode
        :param message: m
        :type message: int
        :param random_seed: r
        :type random_seed: int
        :return: Encoded cipher
        :rtype: str
        """
        return binstr(random_seed, self.n) + self.crypt(message, random_seed)

    def dec(self, cipher: str) -> str:
        """
        Decrypt ciphertext to obtain plaintext message
        :param cipher: ciphertext c
        :type cipher: str
        :return: Decoded message
        :rtype: str
        """
        cipher, random_seed = cipher[self.n:], int(cipher[:self.n], 2)
        return self.crypt(cipher, random_seed)