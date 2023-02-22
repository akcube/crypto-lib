from PRF.PRF import PRF
from util.util import xor, binstr


class CPA:

    def __init__(self,
                 security_parameter: int,
                 prime_field: int,
                 generator: int,
                 key: int,
                 mode="CTR"):
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

    def enc(self, message: str, random_seed: int) -> str:
        """
        Encrypt message against Chosen Plaintext Attack using randomized ctr mode
        :param message: m
        :type message: int
        :param random_seed: ctr
        :type random_seed: int
        """

        blockify = lambda s, block_len: [
            s[i:i + block_len] for i in range(0, len(s), block_len)
        ]
        secret = lambda rs: binstr(self.prf.evaluate(rs), self.n)

        message = blockify(message, self.n)
        cipher = binstr(random_seed, self.n)
        for b in message:
            if self.mode == 'CTR':
                random_seed += 1
                cipher += xor(b, secret(random_seed))
            elif self.mode == 'OFB':
                sec = secret(random_seed)
                cipher += xor(b, sec)
                random_seed = int(sec, 2)
            elif self.mode == 'CBC':
                sec = secret(int(b, 2) ^ random_seed)
                cipher += sec
                random_seed = int(sec, 2)
        return cipher

    def dec(self, cipher: str) -> str:
        """
        Decrypt ciphertext to obtain plaintext message
        :param cipher: ciphertext c
        :type cipher: str
        """
        cipher, rseed = cipher[self.n:], int(cipher[:self.n], 2)
        
