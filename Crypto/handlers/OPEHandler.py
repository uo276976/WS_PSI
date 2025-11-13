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
            pubkey_b64 = cs.serialize_public_key()
            my_data = [int(x) for x in self.my_data]

            coeffs = polinomio_raices(my_data, cs=cs.imp_name)
            enc_coeffs = [cs.encrypt(c) for c in coeffs]
            enc_coeffs = [cs.get_ciphertext(e) for e in enc_coeffs]

            self.send_message(device, enc_coeffs, f"{cs.imp_name} OPE", pubkey_b64)
        return None, None

    def intersection_second_step(self, device, cs, coeffs, pubkey):
        """
        Paso 2: reconstruye PK, evalúa polinomio cifrado y envía resultados cifrados.
        """
        with with_log_context(self, cs, "SECOND_STEP", device):
            my_data = [int(x) for x in self.my_data]
            pubkey = cs.reconstruct_public_key(pubkey)

            coeffs = cs.get_encrypted_list(coeffs, pubkey)
            eval_enc = cs.eval_coefficients(coeffs, pubkey, my_data)
            serialized = cs.serialize_result(eval_enc, "OPE")

            self.send_message(device, serialized, f"{cs.imp_name} OPE")
        return None, None

    def intersection_final_step(self, device, cs, peer_data):
        """
        Paso final: desencripta y devuelve intersección.
        """
        with with_log_context(self, cs, "FINAL_STEP", device):
            result = cs.get_encrypted_list(peer_data)
            result = [int(cs.decrypt(v)) for v in result]
            result_formatted = [e for e in result if e in self.my_data]

            self.results[f"{device} {cs.imp_name} OPE"] = result_formatted
            Logs.log_result(cs.imp_name + '_OPE', result_formatted, VERSION, self.id, device)
            print(f"Intersection with {device} - {cs.imp_name} OPE - Result: {result_formatted}")
        return None, None
