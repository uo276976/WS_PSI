import sys
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity


class KyberHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        # Enviar clave pública
        pubkey = cs.serialize_public_key()
        self.send_message(device, None, cs.imp_name + ' NIKE', pubkey)
        return 0, sys.getsizeof(pubkey)

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        peer_key = cs.reconstruct_public_key(peer_pubkey)
        cs.compute_shared_key(peer_key)
        return 0, 0

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_data):
        ciphertext = bytes.fromhex(peer_data)
        cs.decapsulate_shared_key(ciphertext)
        print(f"[KyberHandler] Shared key with {device}: {cs.shared_key.hex()}")
        self.results[device + " Kyber SharedKey"] = cs.shared_key.hex()
        return None, None
