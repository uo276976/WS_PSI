import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context


class RSAHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results,
                 scheme_name="RSA", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        """Parte A envía su clave pública"""
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pub_b64 = cs.serialize_public_key()
            msg = {"public_key": pub_b64}
            self.send_message(device, None, cs.imp_name, msg, step="1")
            return 0, len(pub_b64.encode())

    def intersection_second_step(self, device, cs, _, peer_data):
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            if isinstance(peer_data, dict) and "public_key" in peer_data:
                peer_pub = cs.deserialize_public_key(peer_data["public_key"])
            elif isinstance(peer_data, str):
                peer_pub = cs.deserialize_public_key(peer_data)
            else:
                raise ValueError(f"Unexpected peer_data format: {type(peer_data)}")

            ciphertext, shared_key = cs.encapsulate(peer_pub)
            cs.shared_key = shared_key

            shared_hex = shared_key.hex()
            self.results[f"{self.id}-{device} RSA SharedKey"] = shared_hex

            ct_b64 = base64.b64encode(ciphertext).decode("utf-8")
            self.send_message(device, ct_b64, cs.imp_name, step="2")

            return 0, len(ct_b64.encode())

    def intersection_final_step(self, device, cs, peer_ct_b64):
        """Parte A decapsula y obtiene la misma clave compartida"""
        with with_log_context(self, cs, "FINAL_STEP", device):
            if not peer_ct_b64:
                raise ValueError("No ciphertext received for RSAHandler final step")

            shared_key = cs.decapsulate(peer_ct_b64)
            cs.shared_key = shared_key

            self._last_key_size_mb = self.measure_mb(shared_key.hex())
            self._last_msg_size_mb = 0.0
            self.results[f"{self.id}-{device} RSA SharedKey"] = shared_key.hex()

        self.stop_persistent_logging()
        return None, None
