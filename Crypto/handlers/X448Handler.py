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
            self.send_message(device, None, cs.imp_name, pub_b64, step="1")
        return None, None

    def intersection_second_step(self, device, cs, _, peer_pub_b64):
        """Parte B encapsula la clave y envía su pública efímera"""
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            _, ss = cs.encapsulate(peer_pub_b64)
            self.results[f"{self.id}-{device} X448 SharedKey"] = ss.hex()
            eph_pub_b64 = cs.get_ciphertext()
            self.send_message(device, eph_pub_b64, cs.imp_name, step="2")
        self.stop_persistent_logging()
        return None, None

    def intersection_final_step(self, device, cs, peer_eph_pub_b64):
        """Parte A decapsula usando la efímera recibida"""
        self.start_persistent_logging()
        with with_log_context(self, cs, "FINAL_STEP", device):
            key_label = f"{self.id}-{device} {self.scheme_name} SharedKey"
            if key_label in self.results:
                self.stop_persistent_logging()
                return None, None

            try:
                ss = cs.decapsulate(peer_eph_pub_b64)
            except Exception:
                self.stop_persistent_logging()
                return None, None

            if not ss:
                self.stop_persistent_logging()
                return None, None

            self.results[key_label] = ss.hex()
        self.stop_persistent_logging()
        return None, None
