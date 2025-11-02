import sys
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
            
            # Handle dict (like hybrid schemes)
            if isinstance(pub, dict):
                pub_serialized = json.dumps(pub)
            else:
                pub_serialized = str(pub)
                
            # print(f"[DEBUG][{self.scheme_name}] Step 1 sending pubkey to {device}: {pub}")
            self.send_message(device, None, cs.imp_name, pub, step="1")
            return 0, len(pub_serialized.encode())

    def intersection_second_step(self, device, cs, _, peer_pubkey):
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            # print(f"[DEBUG][{self.scheme_name}] Step 2 called by {device}")
            norm_pub = peer_pubkey if isinstance(peer_pubkey, dict) else (
                cs.decode_public_key(peer_pubkey) if hasattr(cs, "decode_public_key") else peer_pubkey
            )
            ct, sk = cs.encapsulate(norm_pub)
            
            if isinstance(sk, (bytes, bytearray)):
                sk_hex = sk.hex()
            elif isinstance(sk, str):
                sk_hex = sk.encode().hex()
            else:
                sk_hex = bytes(sk).hex()
            self.results[f"{self.id}-{device} {self.scheme_name} SharedKey"] = sk_hex
            
            # Send ciphertext
            if ct is None and hasattr(cs, "get_ciphertext"):
                data = cs.get_ciphertext()
            else:
                data = base64.b64encode(ct).decode("utf-8") if isinstance(ct, (bytes, bytearray)) else str(ct)
            self.send_message(device, data, cs.imp_name, step="2")
            return 0, len(str(data).encode())

    def intersection_final_step(self, device, cs, peer_data):
        with with_log_context(self, cs, "FINAL_STEP", device):
            # print(f"[DEBUG][{self.scheme_name}] Step 3 decapsulating from {device}")
            sk = cs.decapsulate(peer_data)
            sk_bytes = (
                sk if isinstance(sk, (bytes, bytearray))
                else sk.encode("utf-8") if isinstance(sk, str) else bytes(sk)
            )
            sk_hex = sk_bytes.hex()
            
            self._last_key_size_mb = self.measure_mb(sk_hex)
            self._last_msg_size_mb = 0.0
            
            # print(f"[{self.scheme_name}Handler] Shared key with {device}: {sk_hex}")
            self.results[f"{self.id}-{device} {self.scheme_name} SharedKey"] = sk_hex
        self.stop_persistent_logging()
        return None, None
