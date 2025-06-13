from Network import Node

class IntersectionHandler:
    def __init__(self, id, my_data, domain, devices, results):
        self.id = id
        self.my_data = my_data
        self.domain = domain
        self.devices = devices
        self.results = results

    def send_message(self, peer, ser_enc_res, implementation,
                     peer_pubkey=None, step=None):
        """
        Send a JSON message for any step.
        If `step` is None, defaults to '2' when sending a pubkey, else 'F'.
        """
        if step is None:
            step = '2' if peer_pubkey is not None else 'F'

        msg = {
            'data': ser_enc_res,
            'implementation': implementation,
            'peer': self.id,
            'step': step
        }
        if peer_pubkey is not None:
            msg['pubkey'] = peer_pubkey

        Node.Node.getinstance().send_message(peer, msg)

    def intersection_first_step(self, device, cs):
        raise NotImplementedError

    def intersection_second_step(self, device, cs, peer_data, pubkey):
        raise NotImplementedError

    def intersection_final_step(self, device, cs, peer_data):
        raise NotImplementedError
