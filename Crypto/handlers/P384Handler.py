import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context

class P384Handler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="P-384", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        """Parte A envía su clave pública"""
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pub_b64 = cs.serialize_public_key()
            size = sys.getsizeof(pub_b64)
            # print(f"[P384Handler] Step 1 → sending public key to {device}")
            self.send_message(device, None, cs.imp_name, pub_b64, step="1")
            return 0, size

    def intersection_second_step(self, device, cs, _, peer_pub_b64):
        """Parte B recibe la pública, genera la clave compartida y envía su propia pública"""
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            # print(f"[P384Handler] Step 2 → received pubkey from {device}, computing shared key")
            peer_bytes = base64.b64decode(peer_pub_b64)
            ct, ss = cs.encapsulate(peer_bytes)
            shared_hex = ss.hex()
            self.results[f"{self.id}-{device} P-384 SharedKey"] = shared_hex
            ct_b64 = cs.get_ciphertext()
            size = sys.getsizeof(ct_b64)
            self.send_message(device, ct_b64, cs.imp_name, step="2")
            return 0, size

    def intersection_final_step(self, device, cs, peer_ct_b64):
        """Parte A decapsula y obtiene la misma clave compartida"""
        with with_log_context(self, cs, "FINAL_STEP", device):
            # print(f"[P384Handler] Step 3 → decapsulating from {device}")
            sk = cs.decapsulate(peer_ct_b64)
            hexkey = sk.hex()
            self.results[f"{self.id}-{device} P-384 SharedKey"] = hexkey
            # print(f"[P384Handler] Shared key with {device}: {hexkey}")
        self.stop_persistent_logging()
        return None, None
