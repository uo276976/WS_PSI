import base64
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class X448Helper:
    """
    X448 NIKE helper with HKDF-SHA512 key derivation.
    Produces 32-byte uniform shared keys suitable for symmetric use.
    """
    def __init__(self):
        self.imp_name = "X448"
        self._sk = x448.X448PrivateKey.generate()
        self._pk = self._sk.public_key()
        self._last_ephemeral_pub = None
        self._last_ss = None

    def _derive_key(self, raw_ss: bytes) -> bytes:
        """
        Apply HKDF-SHA512 to the raw shared secret.
        Returns a 32-byte derived key.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b"psi-nike-x448",
        )
        return hkdf.derive(raw_ss)

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
        """
        Generate ephemeral key, compute shared secret with peer,
        return ephemeral pubkey (base64) and derived shared key.
        """
        peer_pub_bytes = self._to_pub_bytes(peer_pub_b64_or_bytes)
        peer_pub = x448.X448PublicKey.from_public_bytes(peer_pub_bytes)
        eph_sk = x448.X448PrivateKey.generate()
        eph_pk_bytes = eph_sk.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )
        raw_ss = eph_sk.exchange(peer_pub)
        derived = self._derive_key(raw_ss)

        self._last_ephemeral_pub = eph_pk_bytes
        self._last_ss = derived
        return base64.b64encode(eph_pk_bytes).decode("utf-8"), derived

    def get_ciphertext(self) -> str:
        if self._last_ephemeral_pub is None:
            raise ValueError("X448 ephemeral not generated yet")
        return base64.b64encode(self._last_ephemeral_pub).decode("utf-8")

    def decapsulate(self, eph_pub_b64_or_bytes):
        eph_bytes = self._to_pub_bytes(eph_pub_b64_or_bytes)
        eph_pub = x448.X448PublicKey.from_public_bytes(eph_bytes)
        raw_ss = self._sk.exchange(eph_pub)
        return self._derive_key(raw_ss)
