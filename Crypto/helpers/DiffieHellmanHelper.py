from Crypto.helpers.CSHelper import CSHelper
import secrets
import hashlib


class DiffieHellmanHelper(CSHelper):
    def __init__(self):
        super().__init__()
        self.imp_name = "Diffie-Hellman"
        self.p = int((
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
        ), 16)  # 2048-bit safe prime
        self.g = 2
        self.private_key = None
        self.public_key = None
        self.shared_key = None
        self.generate_keys()

    def generate_keys(self):
        self.private_key = secrets.randbelow(self.p - 2) + 1  # en rango (1, p-1)
        self.public_key = pow(self.g, self.private_key, self.p)
        print(f"[DH] Public key generated: {self.public_key}")

    def compute_shared_key(self, peer_pubkey):
        peer_pubkey = int(peer_pubkey)
        shared_secret = pow(peer_pubkey, self.private_key, self.p)
        print(f"[DH] Shared secret computed: {shared_secret}")

        # Use SHA-256 as a KDF to derive a fixed-length key
        shared_secret_bytes = str(shared_secret).encode()
        derived_key = hashlib.sha256(shared_secret_bytes).digest()
        self.shared_key = derived_key
        print(f"[DH] Derived key (SHA-256): {derived_key.hex()}")

    def serialize_public_key(self):
        return {'public_key': str(self.public_key)}

    def reconstruct_public_key(self, public_key_dict):
        return int(public_key_dict['public_key'])

    def get_ciphertext(self, value):
        return str(value)

    def serialize_result(self, result, type=None):
        return str(result) if type == "OPE" else result
