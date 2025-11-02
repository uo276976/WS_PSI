import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context

class X448Handler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="X448", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        """Parte A envía su clave pública"""
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pub_b64 = cs.serialize_public_key()
            # print(f"[X448Handler] Step 1 → sending public key to {device}")
            self.send_message(device, None, cs.imp_name, pub_b64, step="1")
            return 0, len(pub_b64.encode())

    def intersection_second_step(self, device, cs, _, peer_pub_b64):
        """Parte B encapsula la clave y envía su pública efímera"""
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            # print(f"[X448Handler] Step 2 → computing shared key with {device}")
            _, ss = cs.encapsulate(peer_pub_b64)
            shared_hex = ss.hex()
            self.results[f"{self.id}-{device} X448 SharedKey"] = shared_hex
            eph_pub_b64 = cs.get_ciphertext()
            self.send_message(device, eph_pub_b64, cs.imp_name, step="2")
            return 0, len(eph_pub_b64)

    def intersection_final_step(self, device, cs, peer_eph_pub_b64):
        """Parte A decapsula usando la efímera recibida"""
        with with_log_context(self, cs, "FINAL_STEP", device):
            # print(f"[X448Handler] Step 3 → decapsulating from {device}")
            ss = cs.decapsulate(peer_eph_pub_b64)
            hexkey = ss.hex()

            self._last_key_size_mb = self.measure_mb(hexkey)
            self._last_msg_size_mb = 0.0

            self.results[f"{self.id}-{device} X448 SharedKey"] = hexkey
            # print(f"[X448Handler] Shared key with {device}: {hexkey}")
        self.stop_persistent_logging()
        return None, None
