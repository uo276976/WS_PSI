import base64
from cryptography.hazmat.primitives.asymmetric import dh, x25519, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from typing import Union

import oqs

# --- NIKE KEM Helpers ---

class PQKEMHelper:
    """Thin wrapper around liboqs KeyEncapsulation."""
    def __init__(self, alg_name: str):
        self.imp_name = alg_name
        self.kem = oqs.KeyEncapsulation(alg_name)
        self.public_key_bytes = self.kem.generate_keypair()
        self.secret_key = self.kem.export_secret_key()
        self.public_key = base64.b64encode(self.public_key_bytes).decode("utf-8")
        self._ciphertext = None

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

    def serialize_public_key(self) -> str:
        return self.public_key

    def decode_public_key(self, pub_input: Union[str, dict]) -> str:
        if isinstance(pub_input, dict):
            return pub_input.get("public_key") or ""
        return pub_input

    def get_ciphertext(self) -> str:
        if self._ciphertext is None:
            return ""
        return base64.b64encode(self._ciphertext).decode("utf-8")

    def set_ciphertext(self, ct: Union[str, bytes]):
        if isinstance(ct, str):
            self._ciphertext = base64.b64decode(ct)
        else:
            self._ciphertext = ct
        self.ciphertext = self._ciphertext

class KyberHelper(PQKEMHelper):
    def __init__(self):
        super().__init__("Kyber512")


class ClassicMcElieceHelper(PQKEMHelper):
    def __init__(self):
        super().__init__("Classic-McEliece-460896")
        
        
class NTRUHelper(PQKEMHelper):
    def __init__(self):
        super().__init__("sntrup761")


class BIKEHelper(PQKEMHelper):
    def __init__(self):
        super().__init__("BIKE-L1")


class HQCHelper(PQKEMHelper):
    def __init__(self):
        super().__init__("HQC-128")


# --- Classic DH Helper ---

class DHHelper:
    def __init__(self):
        self.imp_name = "Diffie-Hellman"
        # 2048-bit group
        params = dh.generate_parameters(generator=2, key_size=2048)
        self.priv = params.generate_private_key()
        self.pub = self.priv.public_key()

    def serialize_public_key(self):
        nums = self.pub.public_numbers()
        return {
            "p": nums.parameter_numbers.p,
            "g": nums.parameter_numbers.g,
            "y": nums.y
        }

    def decode_public_key(self, data):
        pn = dh.DHParameterNumbers(data["p"], data["g"])
        params = pn.parameters()
        return params.load_public_key(
            dh.DHPublicNumbers(data["y"], pn).encode()
        )

    def encapsulate(self, peer_pub):
        shared = self.priv.exchange(peer_pub)
        # derive 32‐byte key
        hkdf = HKDF(hashes.SHA256(), length=32, salt=None, info=b"dh")
        return hkdf.derive(shared)

    def generate_keys(self):
        # regenerate ephemeral keypair
        params = self.priv.parameters()
        self.priv = params.generate_private_key()
        self.pub = self.priv.public_key()


# --- Elliptic Curve Helpers ---

class X25519Helper:
    def __init__(self):
        self.imp_name = "X25519"
        self.priv = x25519.X25519PrivateKey.generate()
        self.pub = self.priv.public_key()
        self.public_key = base64.b64encode(
            self.pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        ).decode("utf-8")
        self._ciphertext = None
        self.ciphertext = None

    def serialize_public_key(self) -> str:
        return self.public_key

    def decode_public_key(self, data: Union[str, dict]) -> str:
        """Devuelve SIEMPRE base64 (string) listo para encapsulate()."""
        if isinstance(data, dict):
            return data.get("public_key")
        return data

    def _ensure_bytes(self, maybe_b64: Union[str, bytes]) -> bytes:
        if isinstance(maybe_b64, str):
            return base64.b64decode(maybe_b64)
        return maybe_b64

    def encapsulate(self, peer_pub: Union[str, bytes]):
        """Acepta pubkey en base64 o bytes; genera ss y 'cifra' el peer_pub (KEM-style)."""
        peer_bytes = self._ensure_bytes(peer_pub)
        ss = self.priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer_bytes))
        self._ciphertext = peer_bytes
        return self._ciphertext, ss

    def decapsulate(self, ciphertext: Union[str, bytes]):
        ct_bytes = self._ensure_bytes(ciphertext)
        return self.priv.exchange(x25519.X25519PublicKey.from_public_bytes(ct_bytes))

    def get_ciphertext(self) -> str:
        return base64.b64encode(self._ciphertext).decode("utf-8")

    def set_ciphertext(self, ct: Union[str, bytes]):
        self.ciphertext = self._ensure_bytes(ct)

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
        """Devuelve SIEMPRE base64 string listo para encapsulate()."""
        if isinstance(data, dict):
            return data.get("public_key")
        return data

    def _ensure_bytes(self, maybe_b64: Union[str, bytes]) -> bytes:
        if isinstance(maybe_b64, str):
            return base64.b64decode(maybe_b64)
        return maybe_b64

    def encapsulate(self, peer_pub: Union[str, bytes]):
        peer_bytes = self._ensure_bytes(peer_pub)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_bytes)
        sk = self.priv.exchange(ec.ECDH(), peer)
        # Igualamos interfaz KEM: el “ciphertext” será el pubkey del emisor (o el peer, según convención).
        # Mantenemos tu convención: devolver peer_pub como ct (luego get_ciphertext lo b64-iza).
        self._ciphertext = peer_bytes
        return self._ciphertext, sk

    def decapsulate(self, ciphertext: Union[str, bytes]):
        ct_bytes = self._ensure_bytes(ciphertext)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ct_bytes)
        return self.priv.exchange(ec.ECDH(), peer)

    def get_ciphertext(self) -> str:
        return base64.b64encode(self._ciphertext).decode("utf-8")

    def set_ciphertext(self, ct: Union[str, bytes]):
        self.ciphertext = self._ensure_bytes(ct)

# --- Hybrid (Kyber + X25519) ---

class HybridKyberX25519Helper:
    def __init__(self):
        self.imp_name = "Hybrid-Kyber-X25519"
        self.pq = KyberHelper()
        self.xc = X25519Helper()
        self.public_key = {
            "pq": self.pq.serialize_public_key(),  # str b64
            "xc": self.xc.serialize_public_key(),  # str b64
        }

    def serialize_public_key(self):
        return {
            "pq": self.pq.serialize_public_key(),
            "xc": self.xc.serialize_public_key(),
        }

    def decode_public_key(self, d):
        """Devuelve dict con base64 strings."""
        return {
            "pq": self.pq.decode_public_key(d["pq"]),
            "xc": self.xc.decode_public_key(d["xc"]),
        }

    def encapsulate(self, peer):
        ct1, ss1 = self.pq.encapsulate(peer["pq"])
        _,   ss2 = self.xc.encapsulate(peer["xc"])
        combo = ss1 + ss2
        hkdf = HKDF(hashes.SHA256(), length=32, salt=None, info=b"hybrid")
        return {
            "pq": self.pq.get_ciphertext(),
            "xc": self.xc.get_ciphertext(),
        }, hkdf.derive(combo)

    def decapsulate(self, ct):
        ss1 = self.pq.decapsulate(ct["pq"])
        ss2 = self.xc.decapsulate(ct["xc"])
        hkdf = HKDF(hashes.SHA256(), length=32, salt=None, info=b"hybrid")
        return hkdf.derive(ss1 + ss2)
    