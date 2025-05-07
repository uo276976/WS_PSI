import oqs
import base64

class ClassicMcElieceHelper:
    def __init__(self):
        self.imp_name = "ClassicMcEliece"
        self.shared_key = None
        self.ciphertext = None
        self.kem = oqs.KeyEncapsulation('Classic-McEliece-348864')
        self.public_key = self.kem.generate_keypair()
        self.secret_key = self.kem.export_secret_key()

    def generate_keys(self):
        self.kem = oqs.KeyEncapsulation('Classic-McEliece-348864')
        self.public_key = self.kem.generate_keypair()

    def serialize_public_key(self):
        return {'public_key': base64.b64encode(self.public_key).decode('utf-8')}

    def reconstruct_public_key(self, public_key_dict):
        return base64.b64decode(public_key_dict['public_key'])

    def compute_shared_key(self, peer_pubkey):
        self.ciphertext, self.shared_key = self.kem.encap(peer_pubkey)

    def decapsulate_shared_key(self, ciphertext):
        self.shared_key = self.kem.decap(ciphertext)

    def get_ciphertext(self):
        return base64.b64encode(self.ciphertext).decode('utf-8')

    def set_ciphertext(self, data_b64):
        self.ciphertext = base64.b64decode(data_b64)
