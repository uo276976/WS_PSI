import sys
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class DHHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="Diffie-Hellman"):
        super().__init__(id, my_data, domain, devices, results)
        self.scheme_name = scheme_name

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        # Step 1: envío pubkey
        my_pub = cs.serialize_public_key()  # dict {"public_key": "..."} (string int)
        size = sys.getsizeof(str(my_pub))
        # 4º parámetro = pubkey cuando step="1"
        self.send_message(device, None, cs.imp_name, my_pub, step="1")
        return 0, size

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        # Step 2: recibo pubkey → computo compartida → envío pubkey para finalizar
        peer_key = cs.reconstruct_public_key(peer_pubkey)
        cs.compute_shared_key(peer_key)

        your_pub = cs.serialize_public_key()
        # 4º parámetro = pubkey cuando step="F"
        self.send_message(device, None, cs.imp_name, your_pub, step="F")
        return 0, sys.getsizeof(str(your_pub))

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_pubkey):
        # Step 3: si aún no tengo la compartida, la calculo con pubkey
        if cs.shared_key is None:
            peer_key = cs.reconstruct_public_key(peer_pubkey)
            cs.compute_shared_key(peer_key)

        hexkey = cs.shared_key.hex()
        print(f"[DHHandler] Shared derived key with {device}: {hexkey}")
        self.results[f"{device} DH SharedKey"] = hexkey
        return None, None
