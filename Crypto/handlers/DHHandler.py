import sys
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class DHHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        # Paso 1: Enviar clave pública
        serialized_pubkey = cs.serialize_public_key()
        self.send_message(device, None, cs.imp_name + ' NIKE', serialized_pubkey)
        size = sys.getsizeof(str(serialized_pubkey))
        return 0, size

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        # Paso 2: Calcular clave compartida
        peer_key = cs.reconstruct_public_key(peer_pubkey)
        cs.compute_shared_key(peer_key)
        return 0, 0

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, _):
        # Solo mostramos el valor, normalmente aquí usarías la clave compartida para algo más
        print(f"[DHHandler] Shared key with {device}: {cs.shared_key}")
        self.results[device + " DH SharedKey"] = cs.shared_key
        if cs.shared_key:
            print(f"[NIKE] Shared key verification: {cs.shared_key[:10]}... (len={len(str(cs.shared_key))})")
        return None, None
