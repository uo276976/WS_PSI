import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context

class KyberHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="Kyber", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pubkey_b64 = cs.serialize_public_key()
            size = sys.getsizeof(pubkey_b64)
            self.send_message(device, None, cs.imp_name, peer_pubkey=pubkey_b64, step="1")
            return 0, size

    def intersection_second_step(self, device, cs, _, peer_pubkey_b64):
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            peer_key_bytes = cs.reconstruct_public_key(peer_pubkey_b64)
            cs.compute_shared_key(peer_key_bytes)
            ciphertext_b64 = cs.get_ciphertext()
            size = sys.getsizeof(ciphertext_b64)
            self.send_message(device, ciphertext_b64, cs.imp_name, step="2")
            return 0, size

    def intersection_final_step(self, device, cs, peer_ciphertext_b64):
        with with_log_context(self, cs, "FINAL_STEP", device):
            if cs.shared_key is None:
                ciphertext = base64.b64decode(peer_ciphertext_b64)
                cs.decapsulate_shared_key(ciphertext)
            hexkey = cs.shared_key.hex()
            # print(f"[KyberHandler] Shared key with {device}: {hexkey}")
            self.results[f"{device} Kyber SharedKey"] = hexkey
        self.stop_persistent_logging()
        return None, None
