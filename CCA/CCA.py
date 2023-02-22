from CBC_MAC.CBC_MAC import CBC_MAC
from CPA.CPA import CPA
from util.util import binstr
from typing import Optional


class CCA:
    """
    This class represents the Chosen Ciphertext Attack (CCA) security model.
    """

    def __init__(self,
                 security_parameter: int,
                 prime_field: int,
                 generator: int,
                 key_cpa: int,
                 key_mac: list[int],
                 cpa_mode="CTR") -> None:
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key_cpa: k1
        :type key_cpa: int
        :param key_mac: k2
        :type key_mac: list[int]
        :param cpa_mode: Block-Cipher mode of operation for CPA
            - CTR
            - OFB
            - CBC
        :type cpa_mode: str
        """
        self.n = security_parameter
        self.cpa = CPA(self.n, prime_field, generator, key_cpa, cpa_mode)
        self.cbc_mac = CBC_MAC(self.n, generator, prime_field, key_mac)

    def enc(self, message: str, cpa_random_seed: int) -> str:
        """
        Encrypt message against Chosen Ciphertext Attack
        :param message: m
        :type message: str
        :param cpa_random_seed: random seed for CPA encryption
        :type cpa_random_seed: int
        :return: encrypted ciphertext
        :rtype: str
        """
        cpa_enc = self.cpa.enc(message, cpa_random_seed)
        return cpa_enc + binstr(self.cbc_mac.mac(cpa_enc))

    def dec(self, cipher: str) -> Optional[str]:
        """
        Decrypt ciphertext to obtain message
        :param cipher: <c, t>
        :type cipher: str
        :return: decrypted message if valid else None
        :rtype: Optional[str]
        """
        c, t = cipher[:-self.n], int(cipher[-self.n:], 2)
        return self.cpa.dec(c) if self.cbc_mac.vrfy(c, t) else None
