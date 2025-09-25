import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class CSIDHHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        # Step 1: enviar mi pubkey (base64 string)
        pubkey_b64 = cs.serialize_public_key()
        print(f"[DEBUG][CSIDH] Step 1 → {device} pubkey_b64({len(pubkey_b64)} chars)")
        self.send_message(device, None, cs.imp_name, pubkey_b64, step="1")
        return 0, sys.getsizeof(pubkey_b64)

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey_b64):
        # Step 2: reconstruyo pubkey del peer, derivo compartida y mando mi pubkey back
        try:
            peer_bytes = cs.reconstruct_public_key(peer_pubkey_b64)
            cs.compute_shared_key(peer_bytes)

            my_pub_b64 = cs.serialize_public_key()
            print(f"[DEBUG][CSIDH] Step 2 → sending my pubkey_b64 to {device}")
            self.send_message(device, my_pub_b64, cs.imp_name, step="2")
            return 0, sys.getsizeof(my_pub_b64)
        except Exception as e:
            print(f"[ERROR][CSIDH] Step 2 failed: {e}")
            raise

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_pubkey_b64):
        try:
            if cs.shared_key is None:
                peer_bytes = cs.reconstruct_public_key(peer_pubkey_b64)
                cs.compute_shared_key(peer_bytes)

            shared_hex = cs.shared_key.hex()
            print(f"[CSIDHHandler] Shared key with {device}: {shared_hex}")
            self.results[f"{device} CSIDH SharedKey"] = shared_hex
            return None, None
        except Exception as e:
            print(f"[ERROR][CSIDH] Final step failed: {e}")
            raise
