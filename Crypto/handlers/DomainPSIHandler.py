import sys
from Logs import Logs
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Network.collections.DbConstants import VERSION
from Logs.LogContext import with_log_context

class DomainPSIHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.category = "PSI-Domain"
        
    def intersection_first_step(self, device, cs):
        with with_log_context(self, cs, "FIRST_STEP", device):
            encrypted_data = cs.encrypt_my_data(self.my_data, self.domain)
            serialized_pubkey = cs.serialize_public_key()
            encrypted_data = {element: cs.get_ciphertext(encrypted_value) for element, encrypted_value in encrypted_data.items()}
            self.send_message(device, encrypted_data, cs.imp_name, serialized_pubkey)
            my_data_size = sum(sys.getsizeof(element) for element in self.my_data)
            ciphertext_size = sum(sys.getsizeof(value) for element, value in encrypted_data.items())
            return my_data_size, ciphertext_size

    def intersection_second_step(self, device, cs, peer_data, pubkey):
        with with_log_context(self, cs, "SECOND_STEP", device):
            pubkey = cs.reconstruct_public_key(pubkey)
            multiplied_set = cs.get_multiplied_set(cs.get_encrypted_set(peer_data, pubkey), self.my_data)
            serialized_multiplied_set = cs.serialize_result(multiplied_set)
            self.send_message(device, serialized_multiplied_set, cs.imp_name)
            ciphertext_size = sum(sys.getsizeof(value) for element, value in serialized_multiplied_set.items())
            return None, ciphertext_size

    def intersection_final_step(self, device, cs, peer_data):
        with with_log_context(self, cs, "FINAL_STEP", device):
            multiplied_set = cs.get_encrypted_set(peer_data)
            for element, encrypted_value in multiplied_set.items():
                multiplied_set[element] = cs.decrypt(encrypted_value)
            multiplied_set = {element for element, value in multiplied_set.items() if value == 2}
            multiplied_set = list(multiplied_set)
            self.results[device + " " + cs.imp_name + " PSI-Domain"] = multiplied_set
            Logs.log_result("INTERSECTION_" + cs.imp_name, multiplied_set, VERSION, self.id, device)
            print(f"Intersection with {device} - {cs.imp_name} - Result: {multiplied_set}")
            return None, None
