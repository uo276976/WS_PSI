import base64
import oqs

class FrodoKEMHelper:
    def __init__(self, scheme="FrodoKEM-640-AES"):
        self.imp_name = "FrodoKEM"
        self.scheme = scheme
        self.category = "NIKE"
        self.kem = oqs.KeyEncapsulation(self.scheme)
        self.public_key = self.kem.generate_keypair()
        self.secret_key = self.kem.export_secret_key()
        self.shared_key = None
        self.ciphertext = None

    def generate_keys(self):
        self.kem = oqs.KeyEncapsulation(self.scheme)
        self.public_key = self.kem.generate_keypair()
        self.shared_key = None
        self.ciphertext = None

    def serialize_public_key(self) -> dict:
        return {"public_key": base64.b64encode(self.public_key).decode("utf-8")}

    def reconstruct_public_key(self, public_key_dict) -> bytes:
        if isinstance(public_key_dict, dict):
            public_key_dict = public_key_dict.get("public_key")
        return base64.b64decode(public_key_dict.encode() if isinstance(public_key_dict, str) else public_key_dict)

    def encapsulate(self, peer_public_key: bytes):
        self.ciphertext, self.shared_key = self.kem.encap_secret(peer_public_key)
        return self.ciphertext, self.shared_key

    def decapsulate(self, ciphertext: bytes):
        self.shared_key = self.kem.decap_secret(ciphertext)
        return self.shared_key

    def get_ciphertext(self) -> str:
        return base64.b64encode(self.ciphertext).decode("utf-8")

    def set_ciphertext(self, data_b64: str):
        self.ciphertext = base64.b64decode(data_b64)
