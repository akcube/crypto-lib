from PRG.PRG import PRG
from util.util import binstr

class PRF:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, key: int) -> None:
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param key: k, uniformly sampled key
        :type key: int
        """
        self.key = key
        self.security_parameter = security_parameter
        self.prg = PRG(security_parameter, generator, prime_field, 2*security_parameter)

    def evaluate(self, x: int) -> int:
        """
        Evaluate the pseudo-random function at `x`
        :param x: input for Fₖ
        :type x: int
        """
        seed = self.key
        for bit in binstr(x, self.security_parameter):
            decstr = self.prg.generate(seed)
            lhalf = len(decstr) // 2
            seed = int(decstr[:lhalf] if bit == '0' else decstr[lhalf:], 2)
        return seed

