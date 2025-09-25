import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class KEMHandler(IntersectionHandler):
    """
    Generic handler for any KEM-based NIKE scheme using helpers with standard methods.
    """
    def __init__(self, id, my_data, domain, devices, results, scheme_name):
        super().__init__(id, my_data, domain, devices, results)
        self.scheme_name = scheme_name

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        pub_b64 = cs.serialize_public_key()
        print(f"[DEBUG][{self.scheme_name}] Step 1 sending pubkey to {device}: {pub_b64}")
        self.send_message(device, None, cs.imp_name, pub_b64, step="1")
        return 0, sys.getsizeof(pub_b64)

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        print(f"[DEBUG][{self.scheme_name}] Step 2 called by {device} with peer pubkey: {peer_pubkey}")
        try:
            # Normalize to base64 string
            if isinstance(peer_pubkey, dict):
                peer_b64 = peer_pubkey.get("public_key")
            elif isinstance(peer_pubkey, bytes):
                peer_b64 = base64.b64encode(peer_pubkey).decode("utf-8")
            else:
                peer_b64 = peer_pubkey

            ct, sk = cs.encapsulate(peer_b64)
            print(f"[DEBUG][{self.scheme_name}] Encapsulated key: {sk.hex()} | Ciphertext: {base64.b64encode(ct).decode('utf-8')}")

            data = cs.get_ciphertext()
            print(f"[DEBUG][{self.scheme_name}] Step 2 sending ciphertext to {device}: {data}")
            self.send_message(device, data, cs.imp_name, step="2")
            return 0, sys.getsizeof(data)

        except Exception as e:
            print(f"[ERROR][{self.scheme_name}] intersection_second_step failed: {e}")
            raise

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_data):
        print(f"[DEBUG][{self.scheme_name}] Step 3 called by {device} with peer ciphertext: {peer_data}")
        try:
            # Normalize ciphertext to bytes
            if isinstance(peer_data, dict):
                peer_data = peer_data.get("ciphertext")
            if isinstance(peer_data, str):
                peer_data = base64.b64decode(peer_data)

            cs.set_ciphertext(peer_data)
            sk = cs.decapsulate(cs.ciphertext)
            print(f"[{self.scheme_name}Handler] Shared key with {device}: {sk.hex()}")
            self.results[f"{device} {self.scheme_name} SharedKey"] = sk.hex()
            return None, None

        except Exception as e:
            print(f"[ERROR][{self.scheme_name}] intersection_final_step failed: {e}")
            raise