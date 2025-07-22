import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.log_activity import log_activity

class KEMHandler(IntersectionHandler):
    """
    Generic handler for any KEM-based NIKE scheme using helpers with standard methods.
    """
    def __init__(self, id, my_data, domain, devices, results, scheme_name):
        super().__init__(id, my_data, domain, devices, results)
        self.scheme_name = scheme_name

    @log_activity("NIKE")
    def intersection_first_step(self, device, cs):
        pub = cs.serialize_public_key()
        print(f"[DEBUG][{self.scheme_name}] Step 1 sending pubkey to {device}: {pub}")
        self.send_message(device, None, cs.imp_name, pub, step="1")
        return 0, sys.getsizeof(pub)

    @log_activity("NIKE")
    def intersection_second_step(self, device, cs, _, peer_pubkey):
        print(f"[DEBUG][{self.scheme_name}] Step 2 called by {device} with peer pubkey: {peer_pubkey}")
    
        try:
            if isinstance(peer_pubkey, dict) or isinstance(peer_pubkey, str):
                peer = cs.decode_public_key(peer_pubkey)
            else:
                raise ValueError("Unsupported peer key format for KEM")
            
            ct, sk = cs.encapsulate(peer)
            print(f"[DEBUG][{self.scheme_name}] Encapsulated key: {sk.hex()} | Ciphertext: {ct}")
            
            data = cs.get_ciphertext()
            print(f"[DEBUG][{self.scheme_name}] Step 2 sending ciphertext to {device}: {data}")
            
            self.send_message(device, data, cs.imp_name, step="2")
            return 0, sys.getsizeof(data)
        
        except Exception as e:
            print(f"[ERROR][{self.scheme_name}] intersection_second_step failed: {e}")
            raise

    @log_activity("NIKE")
    def intersection_final_step(self, device, cs, peer_data):
        print(f"[DEBUG][{self.scheme_name}] Step 3 called by {device} with peer ciphertext: {peer_data}")
        try:
            cs.set_ciphertext(peer_data)
            sk = cs.decapsulate(cs.ciphertext)
            print(f"[{self.scheme_name}Handler] Shared key with {device}: {sk.hex()}")
            self.results[f"{device} {self.scheme_name} SharedKey"] = sk.hex()
            return None, None
        except Exception as e:
            print(f"[ERROR][{self.scheme_name}] intersection_final_step failed: {e}")
            raise