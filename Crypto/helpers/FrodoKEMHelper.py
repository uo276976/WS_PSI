import oqs

class FrodoKEMHelper:
    def __init__(self):
        self.imp_name = "FrodoKEM"
        self.kem = oqs.KeyEncapsulation('FrodoKEM-640-AES')
        self.public_key = self.kem.generate_keypair()
        self.secret_key = self.kem.export_secret_key()

        self.shared_key = None
        self.ciphertext = None

    def generate_keys(self):
        self.kem = oqs.KeyEncapsulation('FrodoKEM-640-AES')
        self.public_key = self.kem.generate_keypair()

    def encapsulate(self, peer_public_key: bytes):
        self.ciphertext, self.shared_key = self.kem.encap(peer_public_key)
        return self.ciphertext, self.shared_key

    def decapsulate(self, ciphertext: bytes):
        self.shared_key = self.kem.decap(ciphertext)
        return self.shared_key
