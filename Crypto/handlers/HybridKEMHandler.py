import concurrent.futures
import json
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logger.LogContext import with_log_context


class HybridKEMHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results,
                 scheme_name="Hybrid-Kyber-X25519", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pub_dict = cs.serialize_public_key()  # {"pq": ..., "xc": ...}
            self.send_message(device, None, cs.imp_name, peer_pubkey=pub_dict, step="1")
        return None, None

    def intersection_second_step(self, device, cs, _, peer_pub_dict):
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            if not isinstance(peer_pub_dict, dict) or "pq" not in peer_pub_dict or "xc" not in peer_pub_dict:
                raise ValueError("[HybridHandler] Expected dict with 'pq' and 'xc' public keys")

            ciphertext, shared_key = cs.encapsulate(peer_pub_dict)

            key_label = f"{self.id}-{device} {self.scheme_name} SharedKey"
            self.results[key_label] = shared_key.hex()

            # ciphertext es un dict {"pq": <b64>, "xc": <b64>}
            self.send_message(device, ciphertext, cs.imp_name, step="2")
        self.stop_persistent_logging()
        return None, None

    def intersection_final_step(self, device, cs, peer_ciphertext):
        self.start_persistent_logging()
        with with_log_context(self, cs, "FINAL_STEP", device):
            key_label = f"{self.id}-{device} {self.scheme_name} SharedKey"

            if key_label in self.results:
                self.stop_persistent_logging()
                return None, None

            if isinstance(peer_ciphertext, (str, bytes)):
                try:
                    peer_ciphertext = json.loads(peer_ciphertext)
                except Exception:
                    self.stop_persistent_logging()
                    return None, None

            if not isinstance(peer_ciphertext, dict) or "pq" not in peer_ciphertext or "xc" not in peer_ciphertext:
                self.stop_persistent_logging()
                return None, None

            try:
                shared_key = cs.decapsulate(peer_ciphertext)
            except Exception:
                self.stop_persistent_logging()
                return None, None

            self.results[key_label] = shared_key.hex()

        self.stop_persistent_logging()
        return None, None
