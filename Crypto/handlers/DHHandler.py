import sys
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class DHHandler(IntersectionHandler):
    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        # Step 1: I send you my pubkey
        my_pub = cs.serialize_public_key()
        size = sys.getsizeof(str(my_pub))
        self.send_message(device, None, cs.imp_name, peer_pubkey=my_pub, step="1")
        return 0, size

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        # Step 2: I receive your pubkey, compute shared, then send you mine back
        peer_key = cs.reconstruct_public_key(peer_pubkey)
        cs.compute_shared_key(peer_key)

        your_pub = cs.serialize_public_key()
        # send back *my* pubkey so you can finish computing
        self.send_message(device, None, cs.imp_name, peer_pubkey=your_pub, step="F")
        return 0, sys.getsizeof(str(your_pub))

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_pubkey):
        # Step 3: I get your pubkey again
        if cs.shared_key is None:
            peer_key = cs.reconstruct_public_key(peer_pubkey)
            cs.compute_shared_key(peer_key)

        hexkey = cs.shared_key.hex()
        print(f"[DHHandler] Shared derived key with {device}: {hexkey}")
        self.results[f"{device} DH SharedKey"] = hexkey
        return None, None