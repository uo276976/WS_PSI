from Crypto.helpers.BaseDiffieHellmanHelper import BaseDiffieHellmanHelper

class DiffieHellmanHelper(BaseDiffieHellmanHelper):
    """RFC 3526 Group 14 (2048-bit) Diffie-Hellman."""
    def __init__(self):
        super().__init__(bits=2048, hash_alg="sha256", name="Diffie-Hellman")

class DiffieHellman8192Helper(BaseDiffieHellmanHelper):
    """RFC 3526 Group 18 (8192-bit) Diffie-Hellman."""
    def __init__(self):
        super().__init__(bits=8192, hash_alg="sha512", name="Diffie-Hellman-8192")
