import json

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
        Send a JSON message for any NIKE or PSI step.
        Compatible with new handlers using with_log_context / log_activity.
        """
        # Step fallback logic
        if step is None:
            step = "2" if peer_pubkey is not None else "F"

        if isinstance(implementation, str):
            implementation = implementation.strip().split()[0].replace("_", "-")

        # Detect device type if available
        device_type = getattr(self, "device_type", None) or getattr(self, "node_device_type", None) or "Unknown"

        # Base message
        msg = {
            "data": ser_enc_res,
            "implementation": implementation,
            "peer": self.id,
            "step": step,
            "device_type": device_type,
            "version": getattr(self, "version", None) or "unknown",
        }

        # Add pubkey if available
        if peer_pubkey is not None:
            msg["pubkey"] = peer_pubkey

        # Optional context metadata (if available)
        if hasattr(self, "scheme_name"):
            msg["scheme_name"] = getattr(self, "scheme_name", implementation)
        if hasattr(self, "category"):
            msg["category"] = getattr(self, "category", None)

        # Debug trace
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[SEND][{timestamp}] → {peer} | step={step} | impl={implementation} | data={bool(ser_enc_res)} | pubkey={bool(peer_pubkey)}")
        except Exception:
            pass

        # Actual send
        try:
            from Network.Node import Node
            node = Node.getinstance()
            if node:
                node.send_message(peer, msg)
            else:
                print(f"[MOCK] Would send to {peer}: {json.dumps(msg, indent=2)}")
        except ImportError:
            print(f"[MOCK] Would send to {peer}: {json.dumps(msg, indent=2)}")

    def intersection_first_step(self, device, cs):
        raise NotImplementedError

    def intersection_second_step(self, device, cs, peer_data, pubkey):
        raise NotImplementedError

    def intersection_final_step(self, device, cs, peer_data):
        raise NotImplementedError
