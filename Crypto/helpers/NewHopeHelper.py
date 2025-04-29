from pqcrypto.kem import newhope512cca

class NewHopeHelper:
    def __init__(self):
        self.imp_name = "NewHope"
        self.public_key = None
        self.private_key = None

    def generate_keys(self, bit_length=None):
        # NewHope no usa bit_length
        self.public_key, self.private_key = newhope512cca.generate_keypair()

    def intersection_first_step(self, peer, cs):
        """
        Primera fase del intercambio: enviar la clave pública a peer.
        """
        # Enviamos nuestro public_key
        return {
            "implementation": self.imp_name,
            "step": "1",
            "peer": peer,
            "pubkey": self.public_key.hex()  # enviar como hex para transmitir
        }

    def intersection_second_step(self, peer, cs, data, pubkey):
        """
        peer recibe public_key del otro y encapsula un secreto
        """
        # Parsear la clave pública recibida
        public_key_bytes = bytes.fromhex(pubkey)

        # Encapsular una clave secreta con la public key recibida
        ciphertext, shared_secret = newhope512cca.encrypt(public_key_bytes)

        # Guardar el shared_secret (temporal)
        cs.shared_secret = shared_secret

        # Devolver el ciphertext para que el peer original pueda descifrar
        return {
            "implementation": self.imp_name,
            "step": "2",
            "peer": peer,
            "data": ciphertext.hex()  # mandar como hex
        }

    def intersection_final_step(self, peer, cs, data):
        """
        peer original recibe el ciphertext y usa su private_key para obtener el shared_secret
        """
        # Parsear el ciphertext
        ciphertext_bytes = bytes.fromhex(data)

        # Decapsular para obtener la shared secret
        shared_secret = newhope512cca.decrypt(ciphertext_bytes, self.private_key)

        # Guardar el resultado
        cs.shared_secret = shared_secret

        return f"Shared secret with {peer} established using NewHope."
