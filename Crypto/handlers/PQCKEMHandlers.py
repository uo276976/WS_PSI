import base64
import json
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logger.LogContext import with_log_context


class KEMHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results,
                 scheme_name=None, device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name or "KEM"

    def intersection_first_step(self, device, cs):
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pubkey = cs.serialize_public_key()
            self.send_message(device, None, cs.imp_name, peer_pubkey=pubkey, step="1")
        return None, None

    def intersection_second_step(self, device, cs, _, peer_pubkey):
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            if isinstance(peer_pubkey, str):
                try:
                    peer_pubkey = json.loads(peer_pubkey)
                except Exception:
                    pass

            peer_bytes = cs.decode_public_key(peer_pubkey)
            ciphertext, shared_key = cs.encapsulate(peer_bytes)

            key_label = f"{self.id}-{device} {self.scheme_name} SharedKey"
            self.results[key_label] = shared_key.hex() if isinstance(shared_key, bytes) else shared_key

            ct_b64 = cs.get_ciphertext() if hasattr(cs, "get_ciphertext") else base64.b64encode(ciphertext).decode("utf-8")
            self.send_message(device, ct_b64, cs.imp_name, step="2")
        self.stop_persistent_logging()
        return None, None

    def intersection_final_step(self, device, cs, peer_ciphertext):
        with with_log_context(self, cs, "FINAL_STEP", device):
            key_label = f"{self.id}-{device} {self.scheme_name} SharedKey"
            if key_label in self.results:
                self.stop_persistent_logging()
                return None, None

            if isinstance(peer_ciphertext, str):
                try:
                    peer_ciphertext = json.loads(peer_ciphertext)
                except Exception:
                    try:
                        peer_ciphertext = base64.b64decode(peer_ciphertext)
                    except Exception:
                        pass

            shared_key = cs.decapsulate(peer_ciphertext)
            self.results[key_label] = shared_key.hex() if isinstance(shared_key, bytes) else shared_key
        self.stop_persistent_logging()
        return None, None
