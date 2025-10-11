import sys
from Logs import Logs
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Network.collections.DbConstants import VERSION
from Crypto.numbers.Polynomials import polinomio_raices
from Logs.LogContext import with_log_context

class CAOPEHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)

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
        serialized_pubkey = cs.serialize_public_key()
        my_data = [int(element) for element in self.my_data]
        coeffs = polinomio_raices(my_data)
        encrypted_coeffs = [cs.encrypt(coeff) for coeff in coeffs]
        encrypted_coeffs = [cs.get_ciphertext(encrypted_coeff) for encrypted_coeff in encrypted_coeffs]
        self.send_message(device, encrypted_coeffs, (cs.imp_name + ' PSI-CA OPE'), serialized_pubkey)
        my_data_size = sum(sys.getsizeof(element) for element in my_data)
        ciphertext_size = sum(sys.getsizeof(element) for element in encrypted_coeffs)
        return my_data_size, ciphertext_size

    def intersection_second_step(self, device, cs, coeffs, pubkey):
        with with_log_context(self, cs, "SECOND_STEP", device):
            my_data = [int(element) for element in self.my_data]
            pubkey = cs.reconstruct_public_key(pubkey)
            coeffs = cs.get_encrypted_list(coeffs, pubkey)
            result = cs.get_evaluations(coeffs, pubkey, my_data)
            serialized_result = cs.serialize_result(result, "OPE")
            self.send_message(device, serialized_result, cs.imp_name + ' PSI-CA OPE')
            ciphertext_size = sum(sys.getsizeof(element) for element in serialized_result)
            return None, ciphertext_size

    def intersection_final_step(self, device, cs, peer_data):
        with with_log_context(self, cs, "FINAL_STEP", device):
            result = cs.get_encrypted_list(peer_data)
            result = [int(cs.decrypt(encrypted_value)) for encrypted_value in result]
            cardinality = sum([int(element == 0) for element in result])
            self.results[device + " " + cs.imp_name + ' PSI-CA_OPE'] = cardinality
            Logs.log_result((cs.imp_name + '_PSI-CA_OPE'), cardinality, VERSION, self.id, device)
            print(f"Cardinality calculation with {device} - {cs.imp_name} PSI-CA OPE - Result: {cardinality}")
            return None, None
