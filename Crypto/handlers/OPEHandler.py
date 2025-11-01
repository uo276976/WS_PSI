import sys
from Logs import Logs
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Network.collections.DbConstants import VERSION
from Crypto.numbers.Polynomials import polinomio_raices
from Logs.LogContext import with_log_context

class OPEHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.category = "OPE"

    def intersection_first_step(self, device, cs):
        """
        This method performs the first step of the intersection operation using Oblivious Polynomial Evaluation (OPE)

        Parameters:
        device (str): The device with which the intersection operation is being performed.
        cs (Cryptosystem): The cryptosystem being used for the operation.

        The method follows these steps:
        1. Serializes the public key of the cryptosystem.
        2. Converts the data to integers and adds them to a list.
        3. Calculates the roots of the polynomial that has the data as coefficients.
        4. Encrypts the coefficients.
        5. Gets the ciphertext of the encrypted coefficients.
        6. Prints the coefficients being sent.
        7. Sends the coefficients to the device.
        """
        with with_log_context(self, cs, "FIRST_STEP", device):
            serialized_pubkey = cs.serialize_public_key()
            my_data = [int(element) for element in self.my_data]
            coeffs = polinomio_raices(my_data, cs=cs.imp_name)
            encrypted_coeffs = [cs.encrypt(coeff) for coeff in coeffs]
            encrypted_coeffs = [cs.get_ciphertext(enc) for enc in encrypted_coeffs]
            self.send_message(device, encrypted_coeffs, (cs.imp_name + ' OPE'), serialized_pubkey)
            my_data_size = sum(sys.getsizeof(e) for e in my_data)
            ciphertext_size = sum(sys.getsizeof(e) for e in encrypted_coeffs)
            return my_data_size, ciphertext_size

    def intersection_second_step(self, device, cs, coeffs, pubkey):
        with with_log_context(self, cs, "SECOND_STEP", device):
            my_data = [int(element) for element in self.my_data]
            pubkey = cs.reconstruct_public_key(pubkey)
            coeffs = cs.get_encrypted_list(coeffs, pubkey)
            encrypted_evaluated_coeffs = cs.eval_coefficients(coeffs, pubkey, my_data)
            serialized_encrypted_evaluated_coeffs = cs.serialize_result(encrypted_evaluated_coeffs, "OPE")
            self.send_message(device, serialized_encrypted_evaluated_coeffs, cs.imp_name + ' OPE')
            ciphertext_size = sum(sys.getsizeof(element) for element in serialized_encrypted_evaluated_coeffs)
            return None, ciphertext_size

    def intersection_final_step(self, device, cs, peer_data):
        with with_log_context(self, cs, "FINAL_STEP", device):
            result = cs.get_encrypted_list(peer_data)
            result = [int(cs.decrypt(encrypted_value)) for encrypted_value in result]
            result_formatted = [element for element in result if element in self.my_data]
            self.results[device + " " + cs.imp_name + ' OPE'] = result_formatted
            Logs.log_result(cs.imp_name + '_OPE', result_formatted, VERSION, self.id, device)
            print(f"Intersection with {device} - {cs.imp_name} OPE - Result: {result_formatted}")
            return None, None
