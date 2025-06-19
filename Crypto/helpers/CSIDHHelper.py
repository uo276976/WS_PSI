from ctypes import CDLL, c_void_p, create_string_buffer
from Crypto.helpers.CSHelper import CSHelper

class CSIDHHelper(CSHelper):
    def __init__(self):
        super().__init__()
        self.imp_name = "CSIDH"
        self.lib = CDLL("./Crypto/csidh_wrapper/libcsidh.so")
        self.pubkey = None
        self.privkey = None
        self.shared_key = None
        self.KEY_SIZE = 64 
        self.PRIV_SIZE = 64

        self.generate_keys()

    def generate_keys(self):
        pub_buf = create_string_buffer(self.KEY_SIZE)
        priv_buf = create_string_buffer(self.KEY_SIZE)
        self.lib.generate_key(pub_buf, priv_buf)
        self.pubkey = pub_buf.raw
        self.privkey = priv_buf.raw
        print("[CSIDH] Claves generadas")

    def compute_shared_key(self, peer_pubkey_bytes):
        shared_buf = create_string_buffer(self.KEY_SIZE)
        peer_buf = create_string_buffer(peer_pubkey_bytes, self.KEY_SIZE)
        priv_buf = create_string_buffer(self.privkey, self.PRIV_SIZE)

        print("[CSIDH] Deriving shared key...")
        self.lib.derive_shared(shared_buf, peer_buf, priv_buf)
        self.shared_key = shared_buf.raw
        print("[CSIDH] Clave compartida derivada:", self.shared_key.hex())

    def serialize_public_key(self):
        return {"public_key": self.pubkey.hex()}

    def reconstruct_public_key(self, pub_dict):
        return bytes.fromhex(pub_dict["public_key"])

    def serialize_result(self, result, type=None):
        return result.hex()

    def get_ciphertext(self, value):
        return value.hex()
