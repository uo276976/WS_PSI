import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logger.LogContext import with_log_context

class ClassicMcElieceHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results,
                 scheme_name="ClassicMcEliece", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        """
        Paso 1: envío de la clave pública del esquema McEliece.
        (El dispositivo A inicia el registro persistente.)
        """
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pubkey_b64 = cs.serialize_public_key()
            self.send_message(device, None, cs.imp_name, peer_pubkey=pubkey_b64, step="1")
        return None, None

    def intersection_second_step(self, device, cs, _, peer_pubkey):
        """
        Paso 2: encapsulación (KEM).
        (El dispositivo B inicia y cierra su propio logging.)
        """
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            peer_key = cs.reconstruct_public_key(peer_pubkey)
            cs.compute_shared_key(peer_key)

            key_label = f"{device} ClassicMcEliece SharedKey"
            self.results[key_label] = cs.shared_key.hex()

            ciphertext_b64 = cs.get_ciphertext()
            self.send_message(device, ciphertext_b64, cs.imp_name, step="2")
        self.stop_persistent_logging()
        return None, None

    def intersection_final_step(self, device, cs, peer_data):
        """
        Paso 3: decapsulación del ciphertext recibido.
        (El dispositivo A cierra el registro persistente iniciado en el paso 1.)
        """
        with with_log_context(self, cs, "FINAL_STEP", device):
            key_label = f"{device} ClassicMcEliece SharedKey"
            if key_label in self.results:
                return None, None

            try:
                cs.decapsulate_shared_key(peer_data)
            except Exception as e:
                print(f"[WARN] Error decapsulating McEliece key: {e}")
                return None, None

            self.results[key_label] = cs.shared_key.hex()

        self.stop_persistent_logging()
        return None, None
