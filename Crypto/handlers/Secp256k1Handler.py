import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context

class Secp256k1Handler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="secp256k1", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        """Parte A envía su clave pública"""
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pub_b64 = cs.serialize_public_key()
            # print(f"[Secp256k1Handler] Step 1 → sending public key to {device}")
            self.send_message(device, None, cs.imp_name, pub_b64, step="1")
            return 0, len(pub_b64.encode())

    def intersection_second_step(self, device, cs, _, peer_pub_b64):
        """Parte B recibe la pública, genera shared key y envía su pública"""
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            ct_b64, ss = cs.encapsulate(peer_pub_b64)
            shared_hex = ss.hex()
            self.results[f"{self.id}-{device} Secp256k1 SharedKey"] = shared_hex
            self.send_message(device, ct_b64, cs.imp_name, step="2")
            return 0, len(ct_b64)

    def intersection_final_step(self, device, cs, peer_ct_b64):
        """Parte A decapsula para obtener shared key"""
        with with_log_context(self, cs, "FINAL_STEP", device):
            # print(f"[Secp256k1Handler] Step 3 → decapsulating from {device}")
            sk = cs.decapsulate(peer_ct_b64)
            hexkey = sk.hex()
            
            self._last_key_size_mb = self.measure_mb(hexkey)
            self._last_msg_size_mb = 0.0
            
            self.results[f"{self.id}-{device} secp256k1 SharedKey"] = hexkey
            # print(f"[Secp256k1Handler] Shared key with {device}: {hexkey}")
        self.stop_persistent_logging()
        return None, None
