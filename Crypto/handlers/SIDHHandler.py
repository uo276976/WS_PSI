from Crypto.helpers.SIDHHelper import SIDHHelper

class SIDHHandler:
    def __init__(self, id, my_data, domain, devices, results):
        self.id = id
        self.my_data = my_data
        self.domain = domain
        self.devices = devices
        self.results = results
        self.helper = SIDHHelper()
        self.helper.generate_keys()

    def intersection_first_step(self, device, cs):
        public_key = self.helper.get_public_key()
        # Enviar la clave pública al dispositivo
        self.send_public_key(device, public_key)

    def intersection_second_step(self, peer, cs, data, pubkey):
        shared_secret = self.helper.compute_shared_secret(pubkey)
        # Procesar el secreto compartido según sea necesario

    def intersection_final_step(self, peer, cs, data):
        # Finalizar el proceso de intercambio de claves
        pass

    def send_public_key(self, device, public_key):
        # Implementar el envío de la clave pública al dispositivo
        pass
