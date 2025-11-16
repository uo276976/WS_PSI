import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logger.LogContext import with_log_context

class P384Handler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="P-384", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        """Paso 1: Parte A envía su clave pública."""
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pub_b64 = cs.serialize_public_key()
            self.send_message(device, None, cs.imp_name, pub_b64, step="1")
        return None, None

    def intersection_second_step(self, device, cs, _, peer_pub_b64):
        """Paso 2: Parte B encapsula y envía ciphertext."""
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            peer_bytes = base64.b64decode(peer_pub_b64)
            ct, ss = cs.encapsulate(peer_bytes)

            self.results[f"{self.id}-{device} P-384 SharedKey"] = ss.hex()

            ct_b64 = cs.get_ciphertext()
            self.send_message(device, ct_b64, cs.imp_name, step="2")
        self.stop_persistent_logging()
        return None, None

    def intersection_final_step(self, device, cs, peer_ct_b64):
        """Paso 3: Parte A decapsula y obtiene la misma clave compartida."""
        with with_log_context(self, cs, "FINAL_STEP", device):
            sk = cs.decapsulate(peer_ct_b64)
            self.results[f"{self.id}-{device} P-384 SharedKey"] = sk.hex()
        self.stop_persistent_logging()
        return None, None
