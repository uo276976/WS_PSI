import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logger.LogContext import with_log_context

class FrodoKEMHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="FrodoKEM", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        with with_log_context(self, cs, "FIRST_STEP", device):
            pubkey = {"public_key": base64.b64encode(cs.public_key).decode("utf-8")}
            self.send_message(device, None, cs.imp_name, pubkey, step="1")
        return None, None

    def intersection_second_step(self, device, cs, _, peer_pubkey):
        with with_log_context(self, cs, "SECOND_STEP", device):
            peer_key = base64.b64decode(peer_pubkey["public_key"])
            ct, _ = cs.encapsulate(peer_key)
            if ct is None:
                raise RuntimeError("FrodoKEM encapsulation failed")

            key_label = f"{device} FrodoKEM SharedKey"
            self.results[key_label] = cs.shared_key.hex()

            data = base64.b64encode(ct).decode("utf-8")
            self.send_message(device, data, cs.imp_name, step="2")
        return None, None

    def intersection_final_step(self, device, cs, peer_data):
        with with_log_context(self, cs, "FINAL_STEP", device):
            key_label = f"{device} FrodoKEM SharedKey"
            if key_label in self.results:
                return None, None

            if isinstance(peer_data, dict):
                return None, None

            try:
                ciphertext = base64.b64decode(peer_data)
                cs.shared_key = cs.decapsulate(ciphertext)
            except Exception:
                return None, None

            self.results[key_label] = cs.shared_key.hex()
        return None, None
