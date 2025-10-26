import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context

class RSAHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="RSA", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            msg = {"public_key": cs.serialize_public_key()}
            self.send_message(device, None, cs.imp_name, msg, step="1")
            return 0, sys.getsizeof(msg)

    def intersection_second_step(self, device, cs, _, peer_data):
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):

            if isinstance(peer_data, dict) and "public_key" in peer_data:
                peer_b64 = peer_data["public_key"]
            elif isinstance(peer_data, str):
                peer_b64 = peer_data
            else:
                raise ValueError(f"Unexpected peer_data format: {type(peer_data)}")

            peer_key = cs.deserialize_public_key(peer_b64)
            shared_key = cs.derive_shared_key(peer_key)

            # guardar resultado
            self.results[f"SharedKey_{device}"] = shared_key

            encoded = base64.b64encode(shared_key).decode("utf-8")
            self.send_message(device, None, cs.imp_name, encoded, step="2")
            return 0, sys.getsizeof(encoded)

    def intersection_final_step(self, device, cs, peer_data):
        with with_log_context(self, cs, "FINAL_STEP", device):
            if not peer_data:
                print(f"[ERROR] No peer data received from {device}")
                return None, None

            # aceptar dict o string
            if isinstance(peer_data, dict) and "public_key" in peer_data:
                peer_b64 = peer_data["public_key"]
            elif isinstance(peer_data, str):
                peer_b64 = peer_data
            else:
                raise ValueError(f"Unexpected peer_data format: {type(peer_data)}")

            peer_key = cs.deserialize_public_key(peer_b64)
            shared_key = cs.derive_shared_key(peer_key)

            self.results[f"SharedKey_{device}"] = shared_key

            return shared_key, len(shared_key)
