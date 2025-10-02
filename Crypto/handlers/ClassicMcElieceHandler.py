import sys
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class ClassicMcElieceHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="ClassicMcEliece"):
        super().__init__(id, my_data, domain, devices, results)
        self.scheme_name = scheme_name

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        """
        Step 1: Alice sends her public key to Bob
        """
        pubkey_b64 = cs.serialize_public_key()
        print(f"[DEBUG][{self.scheme_name}] Sending public key to {device}: {pubkey_b64[:32]}...")
        self.send_message(device, None, cs.imp_name, peer_pubkey=pubkey_b64, step="1")
        return 0, sys.getsizeof(pubkey_b64)

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        """
        Step 2: Bob receives Alice's pubkey, encapsulates shared key, and sends ciphertext
        """
        peer_key = cs.reconstruct_public_key(peer_pubkey)
        cs.compute_shared_key(peer_key)
        
        hexkey = cs.shared_key.hex()
        self.results[f"{device} Kyber SharedKey"] = hexkey
        print(f"[KyberHandler] Shared key with {device}: {hexkey}")

        ciphertext_b64 = cs.get_ciphertext()
        size = sys.getsizeof(ciphertext_b64)
        self.send_message(device, ciphertext_b64, cs.imp_name, step="2")
        return 0, size

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_data):
        """
        Step 3: Alice receives ciphertext and decapsulates shared key
        """
        cs.set_ciphertext(peer_data)
        cs.decapsulate_shared_key(cs.ciphertext)

        derived_key_hex = cs.shared_key.hex()
        print(f"[{self.scheme_name}] Shared key established with {device}: {derived_key_hex}")
        self.results[f"{device} ClassicMcEliece SharedKey"] = derived_key_hex
        return None, None
