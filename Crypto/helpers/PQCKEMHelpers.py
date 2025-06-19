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
        self.public_key = self.kem.generate_keypair()
        self.secret_key = self.kem.export_secret_key()

    def encapsulate(self, peer_public: bytes):
        ct, sk = self.kem.encap_secret(peer_public)
        return ct, sk

    def decapsulate(self, ciphertext: bytes):
        return self.kem.decap_secret(ciphertext)

    def serialize_public_key(self):
        return base64.b64encode(self.public_key).decode("utf-8")

    def decode_public_key(self, pub_input):
        if isinstance(pub_input, dict):
            pub_b64 = pub_input.get("public_key")
        elif isinstance(pub_input, str):
            pub_b64 = pub_input
        else:
            raise ValueError("Unsupported public key format")

        return base64.b64decode(pub_b64)

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

    def serialize_public_key(self):
        return base64.b64encode(
            self.pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        ).decode("utf-8")

    def decode_public_key(self, data: Union[bytes, str]):
        if isinstance(data, str):
            data = base64.b64decode(data)
        return x25519.X25519PublicKey.from_public_bytes(data)

    def encapsulate(self, peer_pub_bytes: bytes):
        ss = self.priv.exchange(
            x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        )
        return peer_pub_bytes, ss

    def decapsulate(self, ciphertext: bytes):
        return self.priv.exchange(
            x25519.X25519PublicKey.from_public_bytes(ciphertext)
        )


class P256Helper:
    def __init__(self):
        self.imp_name = "P-256"
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.pub = self.priv.public_key()

    def serialize_public_key(self):
        return self.pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    def decode_public_key(self, data: bytes):
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)

    def encapsulate(self, peer_pub_bytes: bytes):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), peer_pub_bytes
        )
        sk = self.priv.exchange(ec.ECDH(), peer)
        return peer_pub_bytes, sk

    def decapsulate(self, ciphertext: bytes):
        return self.priv.exchange(
            ec.ECDH(),
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ciphertext)
        )


# --- Hybrid (Kyber + X25519) ---

class HybridKyberX25519Helper:
    def __init__(self):
        self.imp_name = "Hybrid-Kyber-X25519"
        self.pq = KyberHelper()
        self.xc = X25519Helper()

    def serialize_public_key(self):
        return {
            "pq": self.pq.serialize_public_key(),
            "xc": self.xc.serialize_public_key()
        }

    def decode_public_key(self, d):
        return {
            "pq": self.pq.decode_public_key(d["pq"]),
            "xc": self.xc.decode_public_key(d["xc"])
        }

    def encapsulate(self, peer):
        ct1, ss1 = self.pq.encapsulate(peer["pq"])
        _, ss2 = self.xc.encapsulate(peer["xc"])
        # combine
        combo = ss1 + ss2
        hkdf = HKDF(hashes.SHA256(), length=32, salt=None, info=b"hybrid")
        return {"pq": ct1, "xc": peer["xc"]}, hkdf.derive(combo)

    def decapsulate(self, ct):
        ss1 = self.pq.decapsulate(ct["pq"])
        ss2 = self.xc.decapsulate(ct["xc"])
        hkdf = HKDF(hashes.SHA256(), length=32, salt=None, info=b"hybrid")
        return hkdf.derive(ss1 + ss2)
