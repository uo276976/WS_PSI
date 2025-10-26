import oqs
import base64

class ClassicMcElieceHelper:
    def __init__(self):
        self.imp_name = "ClassicMcEliece"
        self.scheme = "Classic-McEliece-348864"
        self.shared_key = None
        self.ciphertext = None
        self.public_key = None
        self.secret_key = None
        self.kem = None
        self.generate_keys()

    def generate_keys(self):
        self.kem = oqs.KeyEncapsulation(self.scheme)
        self.public_key = self.kem.generate_keypair()
        self.secret_key = self.kem.export_secret_key()
        return self.public_key

    def serialize_public_key(self) -> str:
        return base64.b64encode(self.public_key).decode("utf-8")

    def reconstruct_public_key(self, public_key_b64) -> bytes:
        if isinstance(public_key_b64, dict):
            public_key_b64 = public_key_b64.get("public_key")
        return base64.b64decode(public_key_b64)

    def compute_shared_key(self, peer_pubkey: bytes):
        ciphertext, shared_key = self.kem.encap_secret(peer_pubkey)
        self.ciphertext = ciphertext
        self.shared_key = shared_key
        return self.shared_key

    def decapsulate_shared_key(self, ciphertext_b64: str):
        ciphertext = base64.b64decode(ciphertext_b64)
        self.shared_key = self.kem.decap_secret(ciphertext)
        return self.shared_key

    def get_ciphertext(self) -> str:
        return base64.b64encode(self.ciphertext).decode("utf-8")

    def set_ciphertext(self, data_b64: str):
        self.ciphertext = base64.b64decode(data_b64)
