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

        try:
            # Lazy import inside the function to avoid circular import
            from Network.Node import Node
            node = Node.getinstance()
            if node:
                node.send_message(peer, msg)
            else:
                print(f"[TEST-MOCK] Would send to {peer}: {msg}")
        except ImportError:
            # Fallback for unit tests
            print(f"[TEST-MOCK] Would send to {peer}: {msg}")

    def intersection_first_step(self, device, cs):
        raise NotImplementedError

    def intersection_second_step(self, device, cs, peer_data, pubkey):
        raise NotImplementedError

    def intersection_final_step(self, device, cs, peer_data):
        raise NotImplementedError
