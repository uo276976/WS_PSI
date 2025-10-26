import sys
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context


class ClassicMcElieceHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results,
                 scheme_name="ClassicMcEliece", device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name

    def intersection_first_step(self, device, cs):
        self.start_persistent_logging()

        with with_log_context(self, cs, "FIRST_STEP", device):
            pubkey_b64 = cs.serialize_public_key()
            size = sys.getsizeof(pubkey_b64)

            # print(f"[DEBUG][{self.scheme_name}] Sending public key to {device}: {pubkey_b64[:32]}...")
            self.send_message(device, None, cs.imp_name, peer_pubkey=pubkey_b64, step="1")

            return 0, size

    def intersection_second_step(self, device, cs, _, peer_pubkey):
        self.start_persistent_logging()

        with with_log_context(self, cs, "SECOND_STEP", device):
            peer_key = cs.reconstruct_public_key(peer_pubkey)
            cs.compute_shared_key(peer_key)
            hexkey = cs.shared_key.hex()

            self.results[f"{device} ClassicMcEliece SharedKey"] = hexkey
            # print(f"[{self.scheme_name}] Shared key computed with {device}: {hexkey}")

            ciphertext_b64 = cs.get_ciphertext()
            size = sys.getsizeof(ciphertext_b64)
            self.send_message(device, ciphertext_b64, cs.imp_name, step="2")

            return 0, size

    def intersection_final_step(self, device, cs, peer_data):
        with with_log_context(self, cs, "FINAL_STEP", device):
            cs.decapsulate_shared_key(peer_data)
            derived_key_hex = cs.shared_key.hex()

            self.results[f"{device} ClassicMcEliece SharedKey"] = derived_key_hex
            # print(f"[{self.scheme_name}] Shared key established with {device}: {derived_key_hex}")

        self.stop_persistent_logging()
        return None, None
