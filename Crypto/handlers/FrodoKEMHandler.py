import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context

class FrodoKEMHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="FrodoKEM", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pubkey = {"public_key": base64.b64encode(cs.public_key).decode("utf-8")}
            self.send_message(device, None, cs.imp_name, pubkey, step="1")
            return 0, len(str(pubkey).encode())

    def intersection_second_step(self, device, cs, _, peer_pubkey):
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            peer_key = base64.b64decode(peer_pubkey["public_key"])
            ct, _ = cs.encapsulate(peer_key)
            if ct is None:
                raise RuntimeError("FrodoKEM encapsulation failed")
            self.results[f"{device} FrodoKEM SharedKey"] = cs.shared_key.hex()
            # print(f"[FrodoKEMHandler] Shared key with {device}: {cs.shared_key.hex()}")
            data = base64.b64encode(ct).decode("utf-8")
            self.send_message(device, data, cs.imp_name, step="2")
            return 0, sys.getsizeof(data)

    def intersection_final_step(self, device, cs, peer_data):
        with with_log_context(self, cs, "FINAL_STEP", device):
            ciphertext = base64.b64decode(peer_data)
            cs.shared_key = cs.decapsulate(ciphertext)
            # print(f"[FrodoKEMHandler] Shared key with {device}: {cs.shared_key.hex()}")
            
            self._last_key_size_mb = self.measure_mb(cs.shared_key.hex())
            self._last_msg_size_mb = 0.0
            
            self.results[f"{device} FrodoKEM SharedKey"] = cs.shared_key.hex()
        self.stop_persistent_logging()
        return None, None
