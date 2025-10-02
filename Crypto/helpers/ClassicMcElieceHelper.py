import oqs
import base64

class ClassicMcElieceHelper:
    def __init__(self):
        self.imp_name = "ClassicMcEliece"
        self.shared_key = None
        self.ciphertext = None
        self.kem = oqs.KeyEncapsulation("Classic-McEliece-348864")
        self.public_key = self.kem.generate_keypair()
        self.secret_key = self.kem.export_secret_key()

    def generate_keys(self):
        self.kem = oqs.KeyEncapsulation("Classic-McEliece-348864")
        self.public_key = self.kem.generate_keypair()

    def serialize_public_key(self) -> str:
        return base64.b64encode(self.public_key).decode("utf-8")

    def reconstruct_public_key(self, public_key_b64) -> bytes:
        if isinstance(public_key_b64, dict):
            public_key_b64 = public_key_b64.get("public_key")
        return base64.b64decode(public_key_b64)

    def compute_shared_key(self, peer_pubkey: bytes):
        self.ciphertext, self.shared_key = self.kem.encap_secret(peer_pubkey)
        return self.shared_key

    def decapsulate_shared_key(self, ciphertext: bytes):
        self.shared_key = self.kem.decap_secret(ciphertext)
        return self.shared_key

    def get_ciphertext(self) -> str:
        return base64.b64encode(self.ciphertext).decode("utf-8")

    def set_ciphertext(self, data_b64: str):
        self.ciphertext = base64.b64decode(data_b64)
