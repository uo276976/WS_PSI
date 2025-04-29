from sibc import SIDH
from Crypto.helpers.BaseHelper import BaseHelper

class SIDHHelper(BaseHelper):
    def __init__(self):
        self.sidh = SIDH()
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        self.private_key, self.public_key = self.sidh.keygen()

    def get_public_key(self):
        return self.public_key

    def compute_shared_secret(self, peer_public_key):
        return self.sidh.exchange(self.private_key, peer_public_key)
