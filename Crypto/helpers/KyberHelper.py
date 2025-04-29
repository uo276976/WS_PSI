import oqs
from Crypto.helpers.CSHelper import CSHelper

class KyberHelper(CSHelper):
    def __init__(self):
        super().__init__()
        self.imp_name = "Kyber"
        self.shared_key = None
        self.ciphertext = None
        self.kem = oqs.KeyEncapsulation('Kyber512')
        self.public_key = self.kem.generate_keypair()
        print("[Kyber] Key pair generated")

    def generate_keys(self):
        self.kem = oqs.KeyEncapsulation('Kyber512')
        self.public_key = self.kem.generate_keypair()
        print("[Kyber] Key pair regenerated")

    def compute_shared_key(self, peer_pubkey):
        self.ciphertext, self.shared_key = self.kem.encap(peer_pubkey)
        print("[Kyber] Shared key encapsulated")

    def decapsulate_shared_key(self, ciphertext):
        self.shared_key = self.kem.decap(ciphertext)
        print("[Kyber] Shared key decapsulated")

    def serialize_public_key(self):
        return {'public_key': self.public_key.hex()}

    def reconstruct_public_key(self, public_key_dict):
        return bytes.fromhex(public_key_dict['public_key'])

    def serialize_result(self, result, type=None):
        return result.hex() if isinstance(result, bytes) else result

    def get_ciphertext(self, value):
        return value.hex() if isinstance(value, bytes) else str(value)
