from Logger import Logs
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Network.collections.DbConstants import VERSION
from Logger.LogContext import with_log_context

class DomainPSIHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.category = "PSI-Domain"

    def intersection_first_step(self, device, cs):
        """Paso 1: Cifra y envía los datos con la clave pública."""
        self.start_persistent_logging()
        with with_log_context(self, cs, "FIRST_STEP", device):
            encrypted_data = cs.encrypt_my_data(self.my_data, self.domain)
            pub_b64 = cs.serialize_public_key()
            encrypted_data = {k: cs.get_ciphertext(v) for k, v in encrypted_data.items()}
            self.send_message(device, encrypted_data, cs.imp_name, peer_pubkey=pub_b64)
        return None, None

    def intersection_second_step(self, device, cs, peer_data, pubkey):
        """Paso 2: Multiplicación ciega."""
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            pubkey = cs.reconstruct_public_key(pubkey)
            multiplied = cs.get_multiplied_set(cs.get_encrypted_set(peer_data, pubkey), self.my_data)
            serialized = cs.serialize_result(multiplied)
            self.send_message(device, serialized, cs.imp_name)
        self.stop_persistent_logging()
        return None, None

    def intersection_final_step(self, device, cs, peer_data):
        """Paso 3: Desencripta y obtiene la intersección."""
        with with_log_context(self, cs, "FINAL_STEP", device):
            multiplied = cs.get_encrypted_set(peer_data)
            for element, enc_val in multiplied.items():
                multiplied[element] = cs.decrypt(enc_val)
            intersection = [e for e, v in multiplied.items() if v == 2]
            self.results[f"{device} {cs.imp_name} PSI-Domain"] = intersection
            Logs.log_result("INTERSECTION_" + cs.imp_name, intersection, VERSION, self.id, device)
            print(f"Intersection with {device} - {cs.imp_name} - Result: {intersection}")
        self.stop_persistent_logging()
        return None, None
