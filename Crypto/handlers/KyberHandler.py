import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logger.LogContext import with_log_context

class KyberHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="Kyber", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pubkey_b64 = cs.serialize_public_key()
            self.send_message(device, None, cs.imp_name, peer_pubkey=pubkey_b64, step="1")
        return None, None

    def intersection_second_step(self, device, cs, _, peer_pubkey_b64):
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            peer_key_bytes = cs.reconstruct_public_key(peer_pubkey_b64)
            cs.compute_shared_key(peer_key_bytes)

            ct_b64 = cs.get_ciphertext()
            self.send_message(device, ct_b64, cs.imp_name, step="2")
        self.stop_persistent_logging()
        return None, None

    def intersection_final_step(self, device, cs, peer_ciphertext_b64):
        with with_log_context(self, cs, "FINAL_STEP", device):
            if not peer_ciphertext_b64:
                raise ValueError("Kyber empty ciphertext received in KyberHandler")
            if cs.shared_key is None:
                ct = base64.b64decode(peer_ciphertext_b64)
                cs.decapsulate_shared_key(ct)
            self.results[f"{device} Kyber SharedKey"] = cs.shared_key.hex()
        self.stop_persistent_logging()
        return None, None
