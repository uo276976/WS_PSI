import sys
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context

class DHHandler(IntersectionHandler):
    def intersection_first_step(self, device, cs):
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            my_pub = cs.serialize_public_key()
            size = sys.getsizeof(str(my_pub))
            self.send_message(device, None, cs.imp_name, my_pub, step="1")
            return 0, size

    def intersection_second_step(self, device, cs, _, peer_pubkey):
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            peer_key = cs.reconstruct_public_key(peer_pubkey)
            cs.compute_shared_key(peer_key)
            your_pub = cs.serialize_public_key()
            self.send_message(device, None, cs.imp_name, your_pub, step="F")
            return 0, sys.getsizeof(str(your_pub))

    def intersection_final_step(self, device, cs, peer_pubkey):
        with with_log_context(self, cs, "FINAL_STEP", device):
            if cs.shared_key is None:
                peer_key = cs.reconstruct_public_key(peer_pubkey)
                cs.compute_shared_key(peer_key)
            hexkey = cs.shared_key.hex()
            self.results[f"{device} DH SharedKey"] = hexkey
            print(f"[DHHandler] Shared derived key with {device}: {hexkey}")
        self.stop_persistent_logging()
        return None, None
