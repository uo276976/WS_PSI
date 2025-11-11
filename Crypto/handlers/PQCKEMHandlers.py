import base64
import json
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context


class KEMHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name=None, device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name or "KEM"

    def intersection_first_step(self, device, cs):
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pub = cs.serialize_public_key()
            pub_serialized = json.dumps(pub) if isinstance(pub, dict) else str(pub)
            self.send_message(device, None, cs.imp_name, pub, step="1")
            return 0, len(pub_serialized.encode())

    def intersection_second_step(self, device, cs, _, peer_pubkey):
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            if isinstance(peer_pubkey, str):
                try:
                    peer_pubkey = json.loads(peer_pubkey)
                except json.JSONDecodeError:
                    pass

            norm_pub = peer_pubkey if isinstance(peer_pubkey, dict) else (
                cs.decode_public_key(peer_pubkey) if hasattr(cs, "decode_public_key") else peer_pubkey
            )
            ct, sk = cs.encapsulate(norm_pub)

            sk_bytes = sk if isinstance(sk, (bytes, bytearray)) else (
                sk.encode("utf-8") if isinstance(sk, str) else bytes(sk)
            )
            sk_hex = sk_bytes.hex()
            key_label = f"{sorted([self.id, device])[0]}-{sorted([self.id, device])[1]} {self.scheme_name} SharedKey"
            self.results[key_label] = sk_hex

            if ct is None and hasattr(cs, "get_ciphertext"):
                data = cs.get_ciphertext()
            elif isinstance(ct, dict):
                data = json.dumps(ct)
            elif isinstance(ct, (bytes, bytearray)):
                data = base64.b64encode(ct).decode("utf-8")
            else:
                data = str(ct)

            self.send_message(device, data, cs.imp_name, step="2")
            return 0, len(data.encode())

    def intersection_final_step(self, device, cs, peer_data):
        self.start_persistent_logging()
        with with_log_context(self, cs, "FINAL_STEP", device):
            key_label = f"{sorted([self.id, device])[0]}-{sorted([self.id, device])[1]} {self.scheme_name} SharedKey"

            if key_label in self.results:
                self.stop_persistent_logging()
                return None, None

            if isinstance(peer_data, str):
                try:
                    peer_data = json.loads(peer_data)
                except Exception:
                    try:
                        peer_data = base64.b64decode(peer_data)
                    except Exception:
                        pass

            try:
                sk = cs.decapsulate(peer_data)
            except Exception:
                self.stop_persistent_logging()
                return None, None

            if sk is None:
                self.stop_persistent_logging()
                return None, None

            sk_bytes = sk if isinstance(sk, (bytes, bytearray)) else (
                sk.encode("utf-8") if isinstance(sk, str) else bytes(sk)
            )
            sk_hex = sk_bytes.hex()
            self._last_key_size_mb = self.measure_mb(sk_hex)
            self.results[key_label] = sk_hex

        self.stop_persistent_logging()
        return None, None
