import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class P384Helper:
    def __init__(self):
        self.imp_name = "P-384"
        self.category = "NIKE"
        self.priv = ec.generate_private_key(ec.SECP384R1())
        self.pub = self.priv.public_key()

        pub_bytes = self.pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        self.public_key = base64.b64encode(pub_bytes).decode("utf-8")
        self._ciphertext = None
        self.ciphertext = None

    def serialize_public_key(self) -> str:
        return self.public_key

    def decode_public_key(self, data):
        if isinstance(data, dict):
            data = data.get("public_key", "")
        return data

    def _ensure_bytes(self, maybe_b64):
        return base64.b64decode(maybe_b64) if isinstance(maybe_b64, str) else maybe_b64

    def encapsulate(self, peer_pub):
        peer_bytes = self._ensure_bytes(peer_pub)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), peer_bytes)
        sk = self.priv.exchange(ec.ECDH(), peer)
        self._ciphertext = self.pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return self._ciphertext, sk

    def decapsulate(self, ciphertext):
        ct_bytes = self._ensure_bytes(ciphertext)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), ct_bytes)
        return self.priv.exchange(ec.ECDH(), peer)

    def get_ciphertext(self):
        return base64.b64encode(self._ciphertext).decode("utf-8")

    def set_ciphertext(self, ct):
        self.ciphertext = self._ensure_bytes(ct)
