import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context

class ClassicMcElieceHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results,
                 scheme_name="ClassicMcEliece", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pubkey_b64 = cs.serialize_public_key()
            size = len(pubkey_b64.encode())
            self.send_message(device, None, cs.imp_name, peer_pubkey=pubkey_b64, step="1")
            return 0, size

    def intersection_second_step(self, device, cs, _, peer_pubkey):
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            peer_key = cs.reconstruct_public_key(peer_pubkey)
            cs.compute_shared_key(peer_key)
            hexkey = cs.shared_key.hex()
            key_label = f"{device} ClassicMcEliece SharedKey"
            self.results[key_label] = hexkey
            ciphertext_b64 = cs.get_ciphertext()
            self.send_message(device, ciphertext_b64, cs.imp_name, step="2")
            return 0, len(ciphertext_b64.encode())

    def intersection_final_step(self, device, cs, peer_data):
        with with_log_context(self, cs, "FINAL_STEP", device):
            key_label = f"{device} ClassicMcEliece SharedKey"
            if key_label in self.results:
                return None, None

            try:
                cs.decapsulate_shared_key(peer_data)
            except Exception:
                return None, None

            derived_key_hex = cs.shared_key.hex()
            self._last_key_size_mb = self.measure_mb(derived_key_hex)
            self.results[key_label] = derived_key_hex

        self.stop_persistent_logging()
        return None, None
