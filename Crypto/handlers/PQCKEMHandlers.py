import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class KEMHandler(IntersectionHandler):
    """
    Generic handler for any KEM-based NIKE scheme using helpers with standard methods.
    """
    def __init__(self, id, my_data, domain, devices, results, scheme_name):
        super().__init__(id, my_data, domain, devices, results)
        self.scheme_name = scheme_name

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        pub = cs.serialize_public_key()
        self.send_message(device, None, cs.imp_name, pub, step="1")
        return 0, sys.getsizeof(pub)

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        peer = peer_pubkey
        if isinstance(peer_pubkey, dict):
            peer = cs.decode_public_key(peer_pubkey)
        elif isinstance(peer_pubkey, str):
            peer = cs.decode_public_key(peer_pubkey)
        else:
            peer = peer_pubkey
            
        ct, sk = cs.encapsulate(peer)

        data = cs.get_ciphertext()
        self.send_message(device, data, cs.imp_name, step="2")
        return 0, sys.getsizeof(str(data))

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_data):
        cs.set_ciphertext(peer_data)
        sk = cs.decapsulate(cs.ciphertext)
        print(f"[{self.scheme_name}Handler] Shared key with {device}: {sk.hex()}")
        self.results[f"{device} {self.scheme_name} SharedKey"] = sk.hex()
        return None, None