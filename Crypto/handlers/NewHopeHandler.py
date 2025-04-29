class NewHopeHandler:
    def __init__(self, id, my_data, domain, devices, results):
        self.id = id
        self.devices = devices
        self.results = results

    def intersection_second_step(self, peer, cs, data, pubkey):
        """
        Ejecuta el segundo paso (peer encapsula el secreto con la public_key recibida)
        """
        result = cs.intersection_second_step(peer, cs, data, pubkey)

        # Enviar de vuelta el ciphertext al peer original
        device_socket = self.devices[peer]["socket"]
        device_socket.send_json(result)

    def intersection_final_step(self, peer, cs, data):
        """
        El peer original usa el ciphertext para obtener el secreto compartido
        """
        message = cs.intersection_final_step(peer, cs, data)
        self.results[peer] = message
