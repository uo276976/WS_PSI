from FrodoKEM.frodo640.api_frodo640 import FrodoAPI640

class FrodoKEMHelper:
    def __init__(self):
        self.api = FrodoAPI640()
        self.public_key = None
        self.secret_key = None

    def generate_keys(self, bit_length=None, domain=None):
        self.public_key, self.secret_key = self.api.crypto_kem_keypair_frodo640()

    def encapsulate(self, peer_public_key):
        ciphertext, shared_secret = self.api.crypto_kem_enc_frodo640(peer_public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext):
        shared_secret = self.api.crypto_kem_dec_frodo640(ciphertext, self.secret_key)
        return shared_secret