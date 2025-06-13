import sys
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class CSIDHHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        # Step 1: Send public key
        pubkey = cs.serialize_public_key()
        self.send_message(device, None, cs.imp_name, pubkey, step="1")
        return 0, sys.getsizeof(pubkey)

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        # reconstruct + compute on B’s side
        peer_bytes = cs.reconstruct_public_key(peer_pubkey)
        cs.compute_shared_key(peer_bytes)

        # *Send* B’s public key back to A
        pub_dict = cs.serialize_public_key()
        self.send_message(
            device,
            None,
            cs.imp_name,
            pub_dict,
            step="2"
        )
        return 0, 0

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_pubkey):
        if cs.shared_key is None:
            raise RuntimeError("Shared key is missing in final step!")
        
        print(f"[CSIDHHandler] Shared key with {device}: {cs.shared_key.hex()}")
        self.results[f"{device} CSIDH SharedKey"] = cs.shared_key.hex()
        return None, None
