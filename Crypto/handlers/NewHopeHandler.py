import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class NewHopeHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="NewHope"):
        super().__init__(id, my_data, domain, devices, results)
        self.scheme_name = scheme_name

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        """
        Peer A sends its public key to peer B.
        """
        pubkey = {
            "public_key": base64.b64encode(cs.public_key).decode("utf-8")
        }
        self.send_message(device, None, cs.imp_name, pubkey, step="1")
        return 0, sys.getsizeof(pubkey)

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        """
        Peer B receives peer A's public key, encapsulates shared secret,
        and sends ciphertext to peer A, signaling final step.
        """
        peer_key = base64.b64decode(peer_pubkey["public_key"])
        cs.ciphertext, cs.shared_key = cs.encapsulate(peer_key)

        ciphertext_encoded = base64.b64encode(cs.ciphertext).decode("utf-8")
        self.send_message(device, None, cs.imp_name, ciphertext_encoded, step="2")
        return 0, sys.getsizeof(ciphertext_encoded)

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_data):
        """
        Peer A receives ciphertext from peer B and decapsulates shared secret.
        """
        if not peer_data:
            print(f"[ERROR] No ciphertext received from {device}")
            return None, None

        ciphertext = base64.b64decode(peer_data)
        cs.shared_key = cs.decapsulate(ciphertext)

        print(f"[NewHopeHandler] Shared key with {device}: {cs.shared_key.hex()}")
        self.results[device + " NewHope SharedKey"] = cs.shared_key.hex()
        return None, None
