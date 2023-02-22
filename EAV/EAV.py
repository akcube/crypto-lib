from PRG.PRG import PRG
from util.util import xor


class Eavesdrop:

    def __init__(self, security_parameter: int, key: int,
                 expansion_factor: int, generator: int, prime_field: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param key: k, uniformly sampled key
        :type key: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        """
        self.key = key
        self.prg = PRG(security_parameter, generator, prime_field,
                       expansion_factor)

    def enc(self, message: str) -> str:
        """
        Encrypt Message against Eavesdropper Adversary
        :param message: message encoded as bit-string
        :type message: str
        :return: Encrypted cipher
        :rtype: str
        """
        return xor(self.prg.generate(self.key), message)

    def dec(self, cipher: str) -> str:
        """
        Decipher ciphertext
        :param cipher: ciphertext encoded as bit-string
        :type cipher: str
        :return: Decrypted text message
        :rtype: str
        """
        return xor(self.prg.generate(self.key), cipher)
