from Logs import Logs
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Network.collections.DbConstants import VERSION
from Crypto.numbers.Polynomials import polinomio_raices
from Logs.LogContext import with_log_context

class CAOPEHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.category = "PSI-CA"

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
            pubkey_b64 = cs.serialize_public_key()
            my_data = [int(x) for x in self.my_data]

            coeffs = polinomio_raices(my_data)
            encrypted_coeffs = [cs.encrypt(c) for c in coeffs]
            encrypted_coeffs = [cs.get_ciphertext(c) for c in encrypted_coeffs]

            self.send_message(device, encrypted_coeffs, f"{cs.imp_name} PSI-CA OPE", pubkey_b64)
        return None, None

    def intersection_second_step(self, device, cs, coeffs, pubkey):
        """
        Segundo paso:
        - Evalúa los polinomios cifrados y devuelve los resultados cifrados.
        """
        self.start_persistent_logging()
        with with_log_context(self, cs, "SECOND_STEP", device):
            my_data = [int(x) for x in self.my_data]
            pubkey = cs.reconstruct_public_key(pubkey)

            coeffs = cs.get_encrypted_list(coeffs, pubkey)
            result = cs.get_evaluations(coeffs, pubkey, my_data)
            serialized_result = cs.serialize_result(result, "OPE")

            self.send_message(device, serialized_result, f"{cs.imp_name} PSI-CA OPE")
        self.stop_persistent_logging()
        return None, None

    def intersection_final_step(self, device, cs, peer_data):
        """
        Paso final:
        - Desencripta los resultados y calcula la cardinalidad (intersección).
        """
        with with_log_context(self, cs, "FINAL_STEP", device):
            result = cs.get_encrypted_list(peer_data)
            result = [int(cs.decrypt(v)) for v in result]
            cardinality = sum(int(x == 0) for x in result)

            self.results[f"{device} {cs.imp_name} PSI-CA_OPE"] = cardinality
            Logs.log_result(f"{cs.imp_name}_PSI-CA_OPE", cardinality, VERSION, self.id, device)
            print(f"Cardinality with {device} - {cs.imp_name} PSI-CA OPE - Result: {cardinality}")
        self.stop_persistent_logging()
        return None, None
