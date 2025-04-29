import sys
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity


class CSIDHHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        # Paso 1: enviar la clave pública
        pubkey = cs.serialize_public_key()
        self.send_message(device, None, cs.imp_name + ' NIKE', pubkey)
        return 0, sys.getsizeof(pubkey)

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        # Paso 2: derivar la clave compartida con la clave pública recibida
        peer_bytes = cs.reconstruct_public_key(peer_pubkey)
        cs.compute_shared_key(peer_bytes)
        return 0, 0

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, _):
        # Paso 3: mostrar o almacenar la clave compartida
        print(f"[CSIDHHandler] Clave compartida con {device}: {cs.shared_key.hex()}")
        self.results[f"{device} CSIDH SharedKey"] = cs.shared_key.hex()
        return None, None
