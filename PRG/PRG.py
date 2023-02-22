class DLP:
    """
    Class for performing dicrete log computation and finding the hardcore predicate.
    """

    def __init__(self, generator: int, prime_field: int) -> None:
        """
        Initialize values here
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        """
        self.g = generator
        self.p = prime_field

    def evaluate(self, x: int) -> int:
        """
        Perform the discrete log computation [f(x) = g^x mod p]
        :param x: x
        :type x: int
        :return: f(x)
        :rtype: int
        """
        return pow(self.g, x, self.p)

    def hardcore_predicate(self, x: int) -> int:
        """
        Returns the hardcore predicate given the output of dicrete log (The MSB)
        :param x: x
        :type x: int
        :return: The MSB of f(x)
        :rtype: int
        """
        return 1 if (x >= (self.p - 1) // 2) else 0


class PRG:
    """
    Class for generating a n-bit pseudo random number
    """

    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, expansion_factor: int) -> None:
        """
        Initialize values here
        :param security_parameter: n (from 1ⁿ)
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        """
        self.n = security_parameter
        self.p = prime_field
        self.g = generator
        self.l = expansion_factor
        self.owf = DLP(generator, prime_field)

    def generate(self, seed: int) -> str:
        """
        Generate the pseudo-random bit-string from `seed`
        :param seed: uniformly sampled seed
        :type seed: int
        :return: The generated pseudo-random bit-string
        :rtype: str
        """

        def genbit():
            nonlocal seed
            seed, hp = self.owf.evaluate(seed), self.owf.hardcore_predicate(
                seed)
            return str(hp)

        return ''.join(genbit() for _ in range(self.l))
