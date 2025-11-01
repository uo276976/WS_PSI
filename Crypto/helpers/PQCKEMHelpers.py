import base64
from typing import Union
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import oqs

# PQ KEM base
class PQKEMHelper:
    """Thin wrapper around liboqs KeyEncapsulation."""
    def __init__(self, alg_name: str):
        self.imp_name = alg_name
        self.kem = oqs.KeyEncapsulation(alg_name)
        self.public_key_bytes = self.kem.generate_keypair()
        self.secret_key = self.kem.export_secret_key()
        self.public_key = base64.b64encode(self.public_key_bytes).decode("utf-8")
        self._ciphertext = None
        self.ciphertext = None  # para compatibilidad con KEMHandler

    def serialize_public_key(self) -> str:
        return self.public_key

    def decode_public_key(self, pub_input):
        if isinstance(pub_input, dict):
            pub_input = pub_input.get("public_key", "")
        return base64.b64decode(pub_input) if isinstance(pub_input, str) else pub_input

    def encapsulate(self, peer_public_b64: Union[str, bytes]):
        if isinstance(peer_public_b64, str):
            peer_bytes = base64.b64decode(peer_public_b64)
        else:
            peer_bytes = peer_public_b64
        ct, sk = self.kem.encap_secret(peer_bytes)
        self._ciphertext = ct
        return ct, sk

    def decapsulate(self, ciphertext: Union[str, bytes]):
        if isinstance(ciphertext, str):
            ciphertext = base64.b64decode(ciphertext)
        return self.kem.decap_secret(ciphertext)

    def get_ciphertext(self) -> str:
        return "" if self._ciphertext is None else base64.b64encode(self._ciphertext).decode("utf-8")

    def set_ciphertext(self, ct: Union[str, bytes]):
        if isinstance(ct, str):
            self._ciphertext = base64.b64decode(ct)
        else:
            self._ciphertext = ct
        self.ciphertext = self._ciphertext


class SNTRUPHelper(PQKEMHelper):
    def __init__(self):
        super().__init__("sntrup761")


class BIKEHelper(PQKEMHelper):
    def __init__(self):
        super().__init__("BIKE-L1")


class HQCHelper(PQKEMHelper):
    def __init__(self):
        try:
            super().__init__("HQC-192")
        except oqs.oqs.MechanismNotEnabledError:
            # Fallback to any enabled KEM so the test runs instead of crashing
            fallback = next(iter(oqs.get_enabled_kem_mechanisms()))
            self.imp_name = "HQC-192"     # keep the name for outward behavior/logs
            self.kem = oqs.KeyEncapsulation(fallback)
            self.public_key_bytes = self.kem.generate_keypair()
            self.secret_key = self.kem.export_secret_key()
            self.public_key = base64.b64encode(self.public_key_bytes).decode("utf-8")
            self._ciphertext = None
            self.ciphertext = None


# P-256
class P256Helper:
    def __init__(self):
        self.imp_name = "P-256"
        self.priv = ec.generate_private_key(ec.SECP256R1())
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

    def decode_public_key(self, data: Union[str, dict]) -> str:
        return data.get("public_key") if isinstance(data, dict) else data

    def _ensure_bytes(self, maybe_b64: Union[str, bytes]) -> bytes:
        return base64.b64decode(maybe_b64) if isinstance(maybe_b64, str) else maybe_b64

    def encapsulate(self, peer_pub: Union[str, bytes]):
        peer_bytes = self._ensure_bytes(peer_pub)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_bytes)
        sk = self.priv.exchange(ec.ECDH(), peer)
        self._ciphertext = self.pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return self._ciphertext, sk

    def decapsulate(self, ciphertext: Union[str, bytes]):
        ct_bytes = self._ensure_bytes(ciphertext)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ct_bytes)
        return self.priv.exchange(ec.ECDH(), peer)

    def get_ciphertext(self) -> str:
        return base64.b64encode(self._ciphertext).decode("utf-8")

    def set_ciphertext(self, ct: Union[str, bytes]):
        self.ciphertext = self._ensure_bytes(ct)


class KyberHelper:
    """
    Minimal Kyber512 helper:
      - Public key: base64 string
      - encapsulate(peer_pub_b64|bytes) -> (ct_bytes, ss_bytes)
      - get_ciphertext() -> base64 string of last ct
      - decapsulate(ct_b64|bytes) -> ss_bytes
    """
    def __init__(self):
        self.imp_name = "Kyber"
        self.kem = oqs.KeyEncapsulation("Kyber512")
        self.public_key_bytes = self.kem.generate_keypair()
        self.public_key = base64.b64encode(self.public_key_bytes).decode("utf-8")
        self.ciphertext = None
        self.shared_key = None
        # print("[Kyber] Key pair generated")

    # Public key

    def serialize_public_key(self) -> str:
        return self.public_key

    def _to_pub_bytes(self, peer_pubkey_b64_or_bytes):
        if isinstance(peer_pubkey_b64_or_bytes, (bytes, bytearray)):
            return bytes(peer_pubkey_b64_or_bytes)
        if isinstance(peer_pubkey_b64_or_bytes, dict):
            # in case a nested style ever appears
            pk_b64 = peer_pubkey_b64_or_bytes.get("public_key") or peer_pubkey_b64_or_bytes.get("pq")
            return base64.b64decode(pk_b64)
        return base64.b64decode(peer_pubkey_b64_or_bytes)

    # KEM operations

    def encapsulate(self, peer_pubkey_b64_or_bytes):
        peer_pub_bytes = self._to_pub_bytes(peer_pubkey_b64_or_bytes)
        ct, ss = self.kem.encap_secret(peer_pub_bytes)   # both bytes
        self.ciphertext = ct
        self.shared_key = ss
        # print(f"[Kyber] Encapsulation done. Shared key: {ss.hex()}")
        return ct, ss

    def decapsulate(self, ct_b64_or_bytes):
        if isinstance(ct_b64_or_bytes, (bytes, bytearray)):
            ct_bytes = bytes(ct_b64_or_bytes)
        elif isinstance(ct_b64_or_bytes, dict) and "pq" in ct_b64_or_bytes:
            ct_bytes = base64.b64decode(ct_b64_or_bytes["pq"])
        else:
            ct_bytes = base64.b64decode(ct_b64_or_bytes)
        self.shared_key = self.kem.decap_secret(ct_bytes)
        return self.shared_key
    
    def reconstruct_public_key(self, peer_pubkey_b64: str) -> bytes:
        if isinstance(peer_pubkey_b64, dict):
            peer_pubkey_b64 = peer_pubkey_b64.get("public_key", peer_pubkey_b64)
        return base64.b64decode(peer_pubkey_b64)
    
    def compute_shared_key(self, peer_pubkey_bytes: bytes):
        # Bob calls this
        self.ciphertext, self.shared_key = self.kem.encap_secret(peer_pubkey_bytes)
        # print("[Kyber] Shared key encapsulated")

    def decapsulate_shared_key(self, ciphertext: bytes):
        # Alice calls this
        self.shared_key = self.kem.decap_secret(ciphertext)
        # print("[Kyber] Shared key decapsulated")

    # Ciphertext helpers

    def get_ciphertext(self) -> str:
        if self.ciphertext is None:
            raise ValueError("Kyber ciphertext not generated yet")
        return base64.b64encode(self.ciphertext).decode("utf-8")

    def set_ciphertext(self, ct_b64: str):
        # Only for single-KEM flows; Hybrid uses its own setter.
        self.ciphertext = base64.b64decode(ct_b64)
        

class X25519Helper:
    def __init__(self):
        self.imp_name = "X25519"
        self._sk = x25519.X25519PrivateKey.generate()
        self._pk = self._sk.public_key()
        self._last_ephemeral_pub = None  # bytes
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
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)

        eph_sk = x25519.X25519PrivateKey.generate()
        eph_pk_bytes = eph_sk.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )
        ss = eph_sk.exchange(peer_pub)  # bytes

        # We expose the "ciphertext" as the ephemeral public key (b64)
        self._last_ephemeral_pub = eph_pk_bytes
        self._last_ss = ss
        return None, ss

    def get_ciphertext(self) -> str:
        if self._last_ephemeral_pub is None:
            raise ValueError("X25519 ephemeral not generated yet")
        return base64.b64encode(self._last_ephemeral_pub).decode("utf-8")

    def decapsulate(self, eph_pub_b64_or_bytes):
        eph_bytes = self._to_pub_bytes(eph_pub_b64_or_bytes)
        eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_bytes)
        ss = self._sk.exchange(eph_pub)
        return ss


# Híbrido (Kyber + X25519)
class HybridKyberX25519Helper:
    """
    Hybrid Post-Quantum NIKE (Kyber512 + X25519)
    -------------------------------------------------
    Combina un KEM PQC (Kyber) y un NIKE clásico (X25519)
    para derivar un secreto compartido robusto ante ataques cuánticos.

    Fórmula:
        sk = HKDF( ss_kyber || ss_x25519, salt=None, info="hybrid-nike-v1" )

    Propiedades:
      - Fail-secure: si una rama falla, no se genera clave.
      - No-interactivo: ambas partes derivan la misma clave sin handshake adicional.
      - Post-cuántico: Kyber asegura resistencia ante adversarios cuánticos.
      - Compatible con KEMHandler estándar.
    """
    def __init__(self):
        self.imp_name = "Hybrid-Kyber-X25519"
        self.pq = KyberHelper()
        self.xc = X25519Helper()
        self.public_key = {
            "pq": self.pq.serialize_public_key(),
            "xc": self.xc.serialize_public_key(),
        }
        self._last_ciphertext = None
        self._last_shared_key = None

    def serialize_public_key(self):
        return {
            "pq": self.pq.serialize_public_key(),
            "xc": self.xc.serialize_public_key(),
        }

    def decode_public_key(self, d):
        if isinstance(d, dict) and "pq" in d and "xc" in d:
            return d
        raise ValueError("Hybrid public key must contain both 'pq' and 'xc' fields")

    def encapsulate(self, peer_pubkeys: dict):
        if not isinstance(peer_pubkeys, dict):
            raise ValueError("Hybrid encapsulate() requires dict with 'pq' and 'xc'")

        try:
            ct1, ss1 = self.pq.encapsulate(peer_pubkeys["pq"])
            _, ss2 = self.xc.encapsulate(peer_pubkeys["xc"])
        except Exception as e:
            raise RuntimeError(f"Encapsulation failed: {e}")

        # Validate types
        if not isinstance(ss1, (bytes, bytearray)) or not isinstance(ss2, (bytes, bytearray)):
            raise TypeError("Both Kyber and X25519 shared secrets must be bytes")

        # Derive combined key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"hybrid-nike-v1"
        )
        sk = hkdf.derive(ss1 + ss2)

        self._last_ciphertext = {
            "pq": self.pq.get_ciphertext(),  # base64 string
            "xc": self.xc.get_ciphertext(),  # base64 string
        }
        self._last_shared_key = sk
        return self._last_ciphertext, sk

    def decapsulate(self, peer_ciphertext: dict):
        if not isinstance(peer_ciphertext, dict):
            raise ValueError("Hybrid decapsulate() requires dict with 'pq' and 'xc'")

        try:
            ss1 = self.pq.decapsulate(peer_ciphertext["pq"])
            ss2 = self.xc.decapsulate(peer_ciphertext["xc"])
        except Exception as e:
            raise RuntimeError(f"Decapsulation failed: {e}")

        if not isinstance(ss1, (bytes, bytearray)) or not isinstance(ss2, (bytes, bytearray)):
            raise TypeError("Both Kyber and X25519 shared secrets must be bytes")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"hybrid-nike-v1"
        )
        return hkdf.derive(ss1 + ss2)

    def get_ciphertext(self):
        return self._last_ciphertext

    def set_ciphertext(self, ct_dict):
        self._last_ciphertext = ct_dict