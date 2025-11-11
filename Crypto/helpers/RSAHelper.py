import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class RSAHelper:
    """
    Real RSA-based KEM/NIKE.
    - Each node generates its RSA keypair.
    - The peer encrypts a random symmetric key with our public key.
    - Both sides share the same derived symmetric key.
    """
    def __init__(self, bits=2048):
        self.imp_name = "RSA"
        self.category = "NIKE"
        self.bits = bits

        # Generate RSA keypair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.bits
        )
        self.public_key = self.private_key.public_key()

        self.shared_key = None
        self.ciphertext = None

    def serialize_public_key(self) -> str:
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(pub_bytes).decode("utf-8")

    def deserialize_public_key(self, b64_pub: str):
        pub_bytes = base64.b64decode(b64_pub)
        return serialization.load_pem_public_key(pub_bytes)

    def encapsulate(self, peer_public_key):
        """
        Encapsulate a symmetric key using the peer's public RSA key.
        """
        shared_key = os.urandom(32)  # 256-bit symmetric key

        # Encrypt with RSA-OAEP
        ciphertext = peer_public_key.encrypt(
            shared_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        self.shared_key = shared_key
        self.ciphertext = ciphertext
        return ciphertext, shared_key

    def decapsulate(self, ciphertext_b64: str):
        """
        Decrypt ciphertext to recover shared key.
        """
        ciphertext = base64.b64decode(ciphertext_b64)
        shared_key = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.shared_key = shared_key
        return shared_key

    def get_ciphertext(self) -> str:
        return base64.b64encode(self.ciphertext).decode("utf-8") if self.ciphertext else None

    def get_shared_key(self) -> str:
        return base64.b64encode(self.shared_key).decode("utf-8") if self.shared_key else None
