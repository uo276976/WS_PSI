from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logger.LogContext import with_log_context

class DiffieHellmanHandler(IntersectionHandler):
    def intersection_first_step(self, device, cs):
        """Paso 1: Enviar clave pública (g^a mod p)."""
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            pub_b64 = cs.serialize_public_key()
            self.send_message(device, None, cs.imp_name, peer_pubkey=pub_b64, step="1")
        return None, None

    def intersection_second_step(self, device, cs, _, peer_pubkey):
        """Paso 2: Recibir clave del peer, calcular y enviar la propia."""
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            peer_key = cs.reconstruct_public_key(peer_pubkey)
            cs.compute_shared_key(peer_key)
            my_pub = cs.serialize_public_key()
            self.send_message(device, None, cs.imp_name, peer_pubkey=my_pub, step="F")
        self.stop_persistent_logging()
        return None, None

    def intersection_final_step(self, device, cs, peer_pubkey):
        """Paso 3: Calcular clave compartida."""
        with with_log_context(self, cs, "FINAL_STEP", device):
            if cs.shared_key is None:
                peer_key = cs.reconstruct_public_key(peer_pubkey)
                cs.compute_shared_key(peer_key)
            hexkey = cs.shared_key.hex()
            self.results[f"{device} Diffie-Hellman SharedKey"] = hexkey
        self.stop_persistent_logging()
        return None, None
