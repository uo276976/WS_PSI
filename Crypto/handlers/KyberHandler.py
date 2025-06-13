import sys
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class KyberHandler(IntersectionHandler):

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        pubkey = cs.serialize_public_key()
        size   = sys.getsizeof(str(pubkey))
        # step="1" → public key
        self.send_message(device,
                          None,
                          cs.imp_name,
                          peer_pubkey=pubkey,
                          step="1")
        return 0, size

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        # receive peer_pubkey, encapsulate, send ciphertext as step="2"
        peer_key = cs.reconstruct_public_key(peer_pubkey)
        cs.compute_shared_key(peer_key)

        ciphertext_hex = cs.ciphertext.hex()
        size          = sys.getsizeof(ciphertext_hex)
        self.send_message(device,
                          ciphertext_hex,
                          cs.imp_name,
                          step="2")
        return 0, size
    
    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_data):
        # peer_data is the hex‐ciphertext string
        ciphertext = bytes.fromhex(peer_data)
        cs.decapsulate_shared_key(ciphertext)

        hexkey = cs.shared_key.hex()
        print(f"[KyberHandler] Shared key with {device}: {hexkey}")
        self.results[f"{device} Kyber SharedKey"] = hexkey
        return None, None