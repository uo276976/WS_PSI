import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

class Secp256k1Helper:
    def __init__(self):
        self.imp_name = "secp256k1"
        self.category = "NIKE"
        self.curve = ec.SECP256K1()
        self.priv = ec.generate_private_key(self.curve)
        self.pub = self.priv.public_key()

        pub_bytes = self.pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        self.public_key = base64.b64encode(pub_bytes).decode("utf-8")
        self._ciphertext = None

    def serialize_public_key(self):
        return self.public_key

    def _ensure_bytes(self, maybe_b64):
        return base64.b64decode(maybe_b64) if isinstance(maybe_b64, str) else maybe_b64

    def encapsulate(self, peer_pub_b64):
        peer_bytes = self._ensure_bytes(peer_pub_b64)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, peer_bytes)

        shared_secret = self.priv.exchange(ec.ECDH(), peer)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_secret)
        shared_key = digest.finalize()

        ct_bytes = self.pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        ct_b64 = base64.b64encode(ct_bytes).decode("utf-8")

        self._ciphertext = ct_b64
        return ct_b64, shared_key

    def decapsulate(self, peer_ct_b64):
        ct_bytes = self._ensure_bytes(peer_ct_b64)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, ct_bytes)

        shared_secret = self.priv.exchange(ec.ECDH(), peer)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_secret)
        return digest.finalize()

    def get_ciphertext(self):
        return self._ciphertext
