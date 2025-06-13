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
        cs.ciphertext, cs.shared_key = cs.encapsulate(peer_key)

        # Send ciphertext to peer and trigger final step
        data = base64.b64encode(cs.ciphertext).decode("utf-8")
        self.send_message(device, None, cs.imp_name, cs.ciphertext, data, step="2")
        return 0, sys.getsizeof(data)

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_data):
        """
        Step 3: Decapsulate shared secret
        """
        ciphertext = base64.b64decode(peer_data)
        cs.shared_key = cs.decapsulate(ciphertext)
        print(f"[ClassicMcElieceHandler] Shared key with {device}: {cs.shared_key.hex()}")

        self.results[device + " ClassicMcEliece SharedKey"] = cs.shared_key.hex()
        return None, None
