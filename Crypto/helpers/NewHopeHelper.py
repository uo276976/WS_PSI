import base64
from oqs import KeyEncapsulation

class NewHopeHelper:
    def __init__(self):
        self.imp_name = "NewHope"
        self.kem = KeyEncapsulation('ntru_hps2048509')  # A NewHope alternative
        self.public_key = self.kem.generate_keypair()
        self.shared_key = None
        self.ciphertext = None

    def generate_keys(self):
        self.kem = KeyEncapsulation('ntru_hps2048509')
        self.public_key = self.kem.generate_keypair()

    def intersection_first_step(self, peer, cs):
        return {
            "implementation": self.imp_name,
            "step": "1",
            "peer": peer,
            "pubkey": base64.b64encode(self.public_key).decode("utf-8")
        }

    def intersection_second_step(self, peer, cs, data, pubkey):
        peer_key = base64.b64decode(pubkey.encode("utf-8"))
        self.ciphertext, self.shared_key = self.kem.encap(peer_key)
        cs.shared_secret = self.shared_key
        return {
            "implementation": self.imp_name,
            "step": "2",
            "peer": peer,
            "data": base64.b64encode(self.ciphertext).decode("utf-8")
        }

    def intersection_final_step(self, peer, cs, data):
        ciphertext = base64.b64decode(data.encode("utf-8"))
        self.shared_key = self.kem.decap(ciphertext)
        cs.shared_secret = self.shared_key
        return f"Shared secret with {peer} established using NewHope."
