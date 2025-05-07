import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity


class NewHopeHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        """
        Send public key to peer
        """
        pubkey = {
            "public_key": base64.b64encode(cs.public_key).decode("utf-8")
        }
        self.send_message(device, None, cs.imp_name + " NIKE", pubkey)
        return 0, sys.getsizeof(pubkey)

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        """
        Receive peer's public key, encapsulate shared secret
        """
        peer_key = base64.b64decode(peer_pubkey["public_key"])
        cs.ciphertext, cs.shared_key = cs.kem.encap(peer_key)

        # Send ciphertext back to peer
        data = base64.b64encode(cs.ciphertext).decode("utf-8")
        self.send_message(device, None, cs.imp_name + " Ciphertext", data)
        return 0, sys.getsizeof(data)

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_data):
        """
        Decapsulate shared secret from ciphertext
        """
        ciphertext = base64.b64decode(peer_data)
        cs.shared_key = cs.kem.decap(ciphertext)
        print(f"[NewHopeHandler] Shared key with {device}: {cs.shared_key.hex()}")

        self.results[device + " NewHope SharedKey"] = cs.shared_key.hex()
        return None, None
