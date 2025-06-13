import base64
from oqs import KeyEncapsulation

class NewHopeHelper:
    def __init__(self):
        self.imp_name = "NewHope"
        self.kem = KeyEncapsulation('ntru_hps2048509')
        self.public_key = self.kem.generate_keypair()
        self.shared_key = None
        self.ciphertext = None

    def generate_keys(self):
        self.kem = KeyEncapsulation('ntru_hps2048509')
        self.public_key = self.kem.generate_keypair()

    def encapsulate(self, peer_public_key: bytes):
        self.ciphertext, self.shared_key = self.kem.encap(peer_public_key)
        return self.ciphertext, self.shared_key

    def decapsulate(self, ciphertext: bytes):
        self.shared_key = self.kem.decap(ciphertext)
        return self.shared_key
