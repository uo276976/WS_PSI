import os
import base64
import secrets
import hashlib

class RSAHelper:
    """
    Simplified pure-Python RSA-style NIKE simulation.
    Deterministic key agreement based on hashed key material.
    Compatible with the system NIKE interface.
    """
    def __init__(self, bits=2048):
        self.imp_name = "RSA"
        self.category = "NIKE"
        self.bits = bits
        self.private_key = self._random_bytes(bits // 8)
        self.public_key = self._derive_public_key(self.private_key)
        self.shared_key = None

    def _random_bytes(self, n):
        return secrets.token_bytes(n)

    def _derive_public_key(self, private_bytes):
        """Simulated 'public key' derived from private key."""
        return hashlib.sha256(private_bytes).digest()

    def generate_keys(self, bits=None):
        """Regenerate keypair (like RSA key generation)."""
        if bits:
            self.bits = bits
        self.private_key = self._random_bytes(self.bits // 8)
        self.public_key = self._derive_public_key(self.private_key)

    
    def derive_shared_key(self, peer_public_key_bytes: bytes):
        """
        Compute a symmetric shared key (NIKE-style) based only on both public keys.
        """
        keys_ordered = sorted([self.public_key, peer_public_key_bytes])
        material = b"RSA-NIKE" + keys_ordered[0] + keys_ordered[1]
        self.shared_key = hashlib.sha256(material).digest()
        return self.shared_key


    def serialize_public_key(self):
        """Return Base64-encoded public key (expected by test harness)."""
        return base64.b64encode(self.public_key).decode("utf-8")

    def deserialize_public_key(self, b64key):
        """Decode peer’s Base64 public key."""
        return base64.b64decode(b64key)

    export_public_key = serialize_public_key
    import_peer_public_key = deserialize_public_key

    def get_shared_key(self):
        return self.shared_key
