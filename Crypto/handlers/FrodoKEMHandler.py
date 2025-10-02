import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class FrodoKEMHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results, scheme_name="FrodoKEM"):
        super().__init__(id, my_data, domain, devices, results)
        self.scheme_name = scheme_name

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        # Step 1: A envía su pubkey (BASE64 string dentro de dict o string; aquí dict)
        pubkey = {"public_key": base64.b64encode(cs.public_key).decode("utf-8")}
        # 4º parámetro = pubkey cuando step="1"
        self.send_message(device, None, cs.imp_name, pubkey, step="1")
        return 0, sys.getsizeof(str(pubkey))

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        # Step 2: B encapsula con la pubkey de A y envía ciphertext (BASE64 string)
        peer_key = base64.b64decode(peer_pubkey["public_key"])
        ct, sk = cs.encapsulate(peer_key)
        if sk is None:
            raise RuntimeError("KEM encapsulation failed")

        # Guardar la clave compartida desde el lado de Bob
        self.results[f"{device} FrodoKEM SharedKey"] = cs.shared_key.hex()
        print(f"[FrodoKEMHandler] Shared key with {device}: {cs.shared_key.hex()}")

        data = base64.b64encode(ct).decode("utf-8")
        self.send_message(device, data, cs.imp_name, step="2")
        return 0, sys.getsizeof(data)

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_data):
        # Step 3: A decapsula
        ciphertext = base64.b64decode(peer_data)
        cs.shared_key = cs.decapsulate(ciphertext)

        print(f"[FrodoKEMHandler] Shared key with {device}: {cs.shared_key.hex()}")
        self.results[f"{device} FrodoKEM SharedKey"] = cs.shared_key.hex()
        return None, None
