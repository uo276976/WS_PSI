import random

from phe import paillier, EncryptedNumber

from Network.collections.DbConstants import DEFL_KEYSIZE_PAILLIER
from Crypto.helpers.CSHelper import CSHelper


class PaillierHelper(CSHelper):

    def __init__(self):
        super().__init__()
        self.imp_name = "Paillier"
        self.private_key, self.public_key = None, None
        self.generate_keys()

    # Devuelve los objetos clave pública y privada
    def generate_keys(self, bit_length=DEFL_KEYSIZE_PAILLIER):
        # print("Generating Paillier keys - bit length: " + str(bit_length))
        self.public_key, self.private_key = paillier.generate_paillier_keypair(n_length=bit_length)
        # print("Paillier keys generated")

    def serialize_public_key(self):
        # Convertir la clave pública en un diccionario con la n
        public_key_dict = {
            'n': str(self.public_key.n)
        }
        return public_key_dict

    def reconstruct_public_key(self, public_key_dict):
        # Reconstruir la clave pública a partir del diccionario
        return paillier.PaillierPublicKey(n=int(public_key_dict['n']))

    def get_encrypted_set(self, serialized_encrypted_set, public_key=None):
        return {element: EncryptedNumber(public_key, int(ciphertext)) for element, ciphertext in
                serialized_encrypted_set.items()} if public_key is not None else \
            {element: EncryptedNumber(self.public_key, int(ciphertext)) for element, ciphertext
             in serialized_encrypted_set.items()}

    def get_encrypted_list(self, serialized_encrypted_list, public_key=None):
        if public_key is None:
            public_key = self.public_key
        return [EncryptedNumber(public_key, int(ciphertext)) for ciphertext in serialized_encrypted_list]

    # Cifrar los números de los sets con los que arrancamos
    def encrypt(self, number):
        encrypted_number = self.public_key.encrypt(number)
        return encrypted_number

    # Desciframos utilizando la clave privada
    def decrypt(self, encrypted_number):
        decrypted_number = self.private_key.decrypt(encrypted_number)
        return decrypted_number

    def encrypt_my_data(self, my_set, domain):
        return {element: self.public_key.encrypt(1) if element in my_set else self.public_key.encrypt(0) for element in
                range(domain)}

    def get_multiplied_set(self, enc_set, node_set):
        # Propósito de depuración
        # print("Generating the multiplied set")
        result = {}
        for element, encrypted_value in enc_set.items():
            multiplier = int(element) in node_set
            if multiplier is False:
                result[element] = encrypted_value.public_key.encrypt(0)
            else:
                result[element] = encrypted_value * 2
        return result
        # return {element: encrypted_value * int(element in node_set) for element, encrypted_value in enc_set.items()}

    def intersection_enc_size(self, multiplied_set):
        # Suma homomórfica de los elementos del set A
        # La suma, una vez descifrada, nos da el tamaño de la intersección, al ser unos y ceros lo que hay cifrados
        return sum([element.ciphertext for element in multiplied_set.values()])

    def get_ciphertext(self, encrypted_number):
        return str(encrypted_number.ciphertext())

    """ OPE - Oblivious Polynomial Evaluation stuff """

    def horner_encrypted_eval(self, coeffs, x):
        result = coeffs[-1]
        for coef in reversed(coeffs[:-1]):
            result = coef._add_encrypted(x * result)
        return result

    def eval_coefficients(self, coeffs, pubkey, my_data):
        # print("Evaluating the polynomial")
        encrypted_results = []
        for element in my_data:
            rb = random.randint(1, 1000)
            Epbj = self.horner_encrypted_eval(coeffs, element)
            encrypted_results.append(pubkey.encrypt(element)._add_encrypted(rb * Epbj))
        return encrypted_results

    def get_evaluations(self, coeffs, pubkey, my_data):
        evaluations = []
        for element in my_data:
            rb = random.randint(1, 1000)
            Epbj = self.horner_encrypted_eval(coeffs, element)
            evaluations.append(pubkey.encrypt(0)._add_encrypted(rb * Epbj))
        # Randomize the order of the evaluations
        random.shuffle(evaluations)
        return evaluations

    def serialize_result(self, result, type=None):
        return [str(encrypted_value.ciphertext()) for encrypted_value in result] if type == "OPE" else \
            {element: str(encrypted_value.ciphertext()) for element, encrypted_value in result.items()}
