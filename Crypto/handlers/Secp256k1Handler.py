from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logger.LogContext import with_log_context

class Secp256k1Handler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="secp256k1", device_type="Unknown"):
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
        """Parte B recibe la pública, genera shared key y envía su pública"""
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            ciphertext_b64, shared = cs.encapsulate(peer_pub_b64)
            self.results[f"{self.id}-{device} secp256k1 SharedKey"] = shared.hex()
            self.send_message(device, ciphertext_b64, cs.imp_name, step="2")
        self.stop_persistent_logging()
        return None, None

    def intersection_final_step(self, device, cs, peer_ct_b64):
        """Parte A decapsula para obtener shared key"""
        with with_log_context(self, cs, "FINAL_STEP", device):
            shared_key = cs.decapsulate(peer_ct_b64)
            self.results[f"{self.id}-{device} secp256k1 SharedKey"] = shared_key.hex()
        self.stop_persistent_logging()
        return None, None
