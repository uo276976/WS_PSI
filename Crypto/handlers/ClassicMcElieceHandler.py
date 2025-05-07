import sys
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity
import base64

class ClassicMcElieceHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        pubkey = cs.serialize_public_key()
        self.send_message(device, None, cs.imp_name + ' NIKE', pubkey)
        return 0, sys.getsizeof(pubkey)

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        peer_key = cs.reconstruct_public_key(peer_pubkey)
        cs.compute_shared_key(peer_key)
        ciphertext = cs.get_ciphertext()
        self.send_message(device, None, cs.imp_name + ' Ciphertext', ciphertext)
        return 0, sys.getsizeof(ciphertext)

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_data):
        ciphertext = base64.b64decode(peer_data)
        cs.decapsulate_shared_key(ciphertext)
        print(f"[ClassicMcElieceHandler] Shared key with {device}: {cs.shared_key.hex()}")
        self.results[device + " ClassicMcEliece SharedKey"] = cs.shared_key.hex()
        return None, None
