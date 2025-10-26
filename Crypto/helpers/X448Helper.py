import base64
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

class X448Helper:
    def __init__(self):
        self.imp_name = "X448"
        self._sk = x448.X448PrivateKey.generate()
        self._pk = self._sk.public_key()
        self._last_ephemeral_pub = None
        self._last_ss = None

    def serialize_public_key(self) -> str:
        return base64.b64encode(
            self._pk.public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw
            )
        ).decode("utf-8")

    def _to_pub_bytes(self, b64_or_bytes):
        if isinstance(b64_or_bytes, (bytes, bytearray)):
            return bytes(b64_or_bytes)
        if isinstance(b64_or_bytes, dict):
            pk_b64 = b64_or_bytes.get("public_key") or b64_or_bytes.get("xc")
            return base64.b64decode(pk_b64)
        return base64.b64decode(b64_or_bytes)

    def encapsulate(self, peer_pub_b64_or_bytes):
        peer_pub_bytes = self._to_pub_bytes(peer_pub_b64_or_bytes)
        peer_pub = x448.X448PublicKey.from_public_bytes(peer_pub_bytes)
        eph_sk = x448.X448PrivateKey.generate()
        eph_pk_bytes = eph_sk.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )
        ss = eph_sk.exchange(peer_pub)
        self._last_ephemeral_pub = eph_pk_bytes
        self._last_ss = ss
        return None, ss

    def get_ciphertext(self) -> str:
        if self._last_ephemeral_pub is None:
            raise ValueError("X448 ephemeral not generated yet")
        return base64.b64encode(self._last_ephemeral_pub).decode("utf-8")

    def decapsulate(self, eph_pub_b64_or_bytes):
        eph_bytes = self._to_pub_bytes(eph_pub_b64_or_bytes)
        eph_pub = x448.X448PublicKey.from_public_bytes(eph_bytes)
        return self._sk.exchange(eph_pub)
