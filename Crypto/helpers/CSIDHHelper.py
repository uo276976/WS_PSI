from ctypes import CDLL, c_size_t, create_string_buffer, c_void_p
import base64
from Crypto.helpers.CSHelper import CSHelper

class CSIDHHelper(CSHelper):
    def __init__(self):
        super().__init__()
        self.imp_name = "CSIDH"
        self.lib = CDLL("./Crypto/csidh_wrapper/libcsidh.so")

        try:
            self.lib.csidh_pubkey_size.restype  = c_size_t
            self.lib.csidh_privkey_size.restype = c_size_t
            self.lib.csidh_shared_size.restype  = c_size_t
            self.KEY_SIZE  = self.lib.csidh_pubkey_size()
            self.PRIV_SIZE = self.lib.csidh_privkey_size()
            self.SHARED_SIZE = self.lib.csidh_shared_size()
        except AttributeError:
            self.KEY_SIZE = 64
            self.PRIV_SIZE = 64
            self.SHARED_SIZE = 64

        self.lib.generate_key.argtypes = [c_void_p, c_void_p]
        self.lib.derive_shared.argtypes = [c_void_p, c_void_p, c_void_p]

        self.pubkey = None
        self.privkey = None
        self.shared_key = None

        self.generate_keys()

    def generate_keys(self):
        pub_buf  = create_string_buffer(self.KEY_SIZE)
        priv_buf = create_string_buffer(self.PRIV_SIZE)
        self.lib.generate_key(pub_buf, priv_buf)
        self.pubkey  = pub_buf.raw
        self.privkey = priv_buf.raw
        print(f"[CSIDH] Claves generadas (pub={len(self.pubkey)}, priv={len(self.privkey)})")

    def compute_shared_key(self, peer_pubkey_bytes: bytes):
        if not isinstance(peer_pubkey_bytes, (bytes, bytearray)):
            raise TypeError("peer_pubkey_bytes debe ser bytes.")
        if len(peer_pubkey_bytes) != self.KEY_SIZE:
            raise ValueError(f"peer_pubkey_bytes debe medir {self.KEY_SIZE}, recibido {len(peer_pubkey_bytes)}")

        shared_buf = create_string_buffer(self.SHARED_SIZE)
        peer_buf   = create_string_buffer(peer_pubkey_bytes, self.KEY_SIZE)
        priv_buf   = create_string_buffer(self.privkey,     self.PRIV_SIZE)

        print("[CSIDH] Deriving shared key...")
        self.lib.derive_shared(shared_buf, peer_buf, priv_buf)
        self.shared_key = shared_buf.raw
        print("[CSIDH] Clave compartida derivada:", self.shared_key.hex())

    # --- Serialización en base64
    def serialize_public_key(self) -> str:
        return base64.b64encode(self.pubkey).decode("utf-8")

    def reconstruct_public_key(self, pubkey_b64: str) -> bytes:
        if isinstance(pubkey_b64, dict):
            pubkey_b64 = pubkey_b64.get("public_key")
        if not isinstance(pubkey_b64, str):
            raise TypeError("Public key debe ser base64 (str).")
        return base64.b64decode(pubkey_b64)

    def serialize_result(self, result, type=None):
        return result.hex() if isinstance(result, (bytes, bytearray)) else str(result)

    def get_ciphertext(self, value):
        return base64.b64encode(value).decode("utf-8") if isinstance(value, (bytes, bytearray)) else str(value)