import random

from damgard_jurik import keygen, EncryptedNumber, PublicKey

from Network.collections.DbConstants import DEFL_EXPANSIONFACTOR, DEFL_KEYSIZE_DAMGARD
from Crypto.helpers.CSHelper import CSHelper


class DamgardJurikHelper(CSHelper):

    def __init__(self):
        super().__init__()
        self.imp_name = "Damgard-Jurik"
        self.public_key, self.private_key = None, None
        self.generate_keys()

    def generate_keys(self, bit_length=DEFL_KEYSIZE_DAMGARD):
        # //2 because of the keygen on Android, to match the keygen on Paillier as well, the effective key size is the
        # product of p and q, but these are 2048 bits long, so the effective key size would be 4096 bits if this is not
        # divided by 2.
        # print("Generating Damgard-Jurik keys - bit length: " + str(bit_length) + " - This operation uses safe primes," + " it could take up to a minute")
        self.public_key, self.private_key = keygen(n_bits=bit_length//2, s=DEFL_EXPANSIONFACTOR, threshold=1, n_shares=1)
        # print("Damgard-Jurik keys generated")

    def encrypt(self, number):
        return self.public_key.encrypt(number)

    def decrypt(self, number):
        return self.private_key.decrypt(number)

    def serialize_public_key(self):
        public_key_dict = {
            'n': str(self.public_key.n),
            's': str(self.public_key.s), 
            'm': str(self.public_key.m),
            'threshold': str(self.public_key.threshold),
            'delta': str(self.public_key.delta)
        }
        return public_key_dict

    def reconstruct_public_key(self, public_key_dict):
        # Si proviene de un dispositivo Android, no traerá ni m, threshold ni delta, por lo que los marcaremos a 1
        # por defecto, no hacen falta para el cifrado
        if 'm' not in public_key_dict:
            return PublicKey(int(public_key_dict['n']), int(public_key_dict['s']), 1, 1, 1)
        return PublicKey(int(public_key_dict['n']), int(public_key_dict['s']), int(public_key_dict['m']),
                         int(public_key_dict['threshold']), int(public_key_dict['delta']))

    def get_encrypted_set(self, serialized_encrypted_set, public_key=None):
        return {element: EncryptedNumber(int(ciphertext), public_key) for element, ciphertext in
                serialized_encrypted_set.items()} if public_key is not None else \
            {element: EncryptedNumber(int(ciphertext), self.public_key) for element, ciphertext
             in serialized_encrypted_set.items()}

    def get_encrypted_list(self, serialized_encrypted_list, public_key=None):
        if public_key is None:
            public_key = self.public_key
        return [EncryptedNumber(int(ciphertext), public_key) for ciphertext in serialized_encrypted_list]

    def encrypt_my_data(self, my_set, domain):
        return {element: self.public_key.encrypt(1) if element in my_set else self.public_key.encrypt(0) for element in
                range(domain)}

    def get_multiplied_set(self, enc_set, node_set):
        # print("Generating the multiplied set")
        result = {}
        for element, encrypted_value in enc_set.items():
            multiplier = int(element) in node_set
            if multiplier is False:
                result[element] = encrypted_value.public_key.encrypt(0)
            else:
                result[element] = encrypted_value * 2
        return result

    def intersection_enc_size(self, multiplied_set):
        return sum([int(element.value) for element in multiplied_set.values()])

    def get_ciphertext(self, encrypted_number):
        return str(encrypted_number.value)

    """ OPE stuff """

    def horner_encrypted_eval(self, coefs, x):
        result = coefs[-1]
        for coef in reversed(coefs[:-1]):
            result = coef.__add__(x * result)
        return result

    def eval_coefficients(self, coefs, pubkey, my_data):
        # print("Evaluating the polynomial")
        encrypted_results = []
        for element in my_data:
            rb = random.randint(1, 1000)
            Epbj = self.horner_encrypted_eval(coefs, element)
            encrypted_results.append(pubkey.encrypt(element) + rb * Epbj)
        return encrypted_results

    def get_evaluations(self, coefs, pubkey, my_data):
        # print("Evaluating the polynomial")
        evaluations = []
        for element in my_data:
            rb = random.randint(1, 1000)
            Epbj = self.horner_encrypted_eval(coefs, element)
            evaluations.append(pubkey.encrypt(0) + rb * Epbj)
        random.shuffle(evaluations)
        return evaluations

    def serialize_result(self, result, type=None):
        return [str(element.value) for element in result] if type == "OPE" else \
            {element: str(encrypted_value.value) for element, encrypted_value in result.items()}
