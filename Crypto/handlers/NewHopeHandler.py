import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context

class NewHopeHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="NewHope", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pubkey = {"public_key": base64.b64encode(cs.public_key).decode("utf-8")}
            self.send_message(device, None, cs.imp_name, pubkey, step="1")
            return 0, sys.getsizeof(pubkey)

    def intersection_second_step(self, device, cs, _, peer_pubkey):
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            peer_key = base64.b64decode(peer_pubkey["public_key"])
            cs.ciphertext, cs.shared_key = cs.encapsulate(peer_key)
            ciphertext_encoded = base64.b64encode(cs.ciphertext).decode("utf-8")
            self.send_message(device, None, cs.imp_name, ciphertext_encoded, step="2")
            return 0, sys.getsizeof(ciphertext_encoded)

    def intersection_final_step(self, device, cs, peer_data):
        with with_log_context(self, cs, "FINAL_STEP", device):
            if not peer_data:
                print(f"[ERROR] No ciphertext received from {device}")
                return None, None
            cipher
