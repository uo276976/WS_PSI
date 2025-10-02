import base64
import oqs
from Crypto.helpers.CSHelper import CSHelper

class KyberHelper(CSHelper):
    def __init__(self):
        super().__init__()
        self.imp_name = "Kyber"
        self.shared_key = None
        self.ciphertext = None
        self.kem = oqs.KeyEncapsulation('Kyber512')
        
        # Generar par de claves inicial
        self.public_key_bytes = self.kem.generate_keypair()
        self.public_key = base64.b64encode(self.public_key_bytes).decode("utf-8")
        print("[Kyber] Key pair generated")

    def generate_keys(self):
        self.kem = oqs.KeyEncapsulation('Kyber512')
        self.public_key_bytes = self.kem.generate_keypair()
        self.public_key = base64.b64encode(self.public_key_bytes).decode("utf-8")
        print("[Kyber] Key pair regenerated")

    def serialize_public_key(self) -> str:
        """Return base64 string of the public key."""
        return self.public_key

    def reconstruct_public_key(self, peer_pubkey_b64: str) -> bytes:
        """
        Reconstruye la clave pública del peer.
        Acepta string base64 y devuelve bytes.
        """
        if isinstance(peer_pubkey_b64, dict):
            peer_pubkey_b64 = peer_pubkey_b64.get("public_key", peer_pubkey_b64)
        return base64.b64decode(peer_pubkey_b64)

    def compute_shared_key(self, peer_pubkey_bytes: bytes):
        """Encapsulate using peer's public key (bytes)."""
        self.ciphertext, self.shared_key = self.kem.encap_secret(peer_pubkey_bytes)
        print("[Kyber] Shared key encapsulated")

    def decapsulate_shared_key(self, ciphertext: bytes):
        """Decapsulate shared key from ciphertext bytes."""
        self.shared_key = self.kem.decap_secret(ciphertext)
        print("[Kyber] Shared key decapsulated")

    def get_ciphertext(self) -> str:
        """Return base64 ciphertext."""
        return base64.b64encode(self.ciphertext).decode("utf-8")

    def set_ciphertext(self, ct_b64: str):
        self.ciphertext = base64.b64decode(ct_b64)