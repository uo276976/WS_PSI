import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class ClassicMcElieceHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        """
        Step 1: Send public key
        """
        pubkey = cs.serialize_public_key()
        self.send_message(device, None, cs.imp_name, pubkey, step="1")
        return 0, sys.getsizeof(pubkey)

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        """
        Step 2: Encapsulate shared secret and send ciphertext
        """
        peer_key = cs.reconstruct_public_key(peer_pubkey)
        cs.compute_shared_key(peer_key)

        # Send ciphertext to peer and trigger final step
        data = cs.get_ciphertext()
        self.send_message(device, data, cs.imp_name, step="2")
        return 0, sys.getsizeof(data)

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_data):
        cs.set_ciphertext(peer_data)
        cs.decapsulate_shared_key(cs.ciphertext)

        print(f"[ClassicMcElieceHandler] Shared key with {device}: {cs.shared_key.hex()}")
        self.results[f"{device} ClassicMcEliece SharedKey"] = cs.shared_key.hex()
        return None, None
