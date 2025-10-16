import sys
import base64
from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs.LogContext import with_log_context


class KEMHandler(IntersectionHandler):
    """
    Generic handler for any KEM-based NIKE scheme using helpers with standard methods.
    """
    def __init__(self, id, my_data, domain, devices, results, scheme_name=None, device_type="Unknown"):
        super().__init__(id, my_data, domain, devices, results, device_type)
        self.scheme_name = scheme_name or "KEM"

    def intersection_first_step(self, device, cs):
        with with_log_context(self, cs, "FIRST_STEP", device):
            pub = cs.serialize_public_key()  # puede ser str b64 o dict (híbrido)
            print(f"[DEBUG][{self.scheme_name}] Step 1 sending pubkey to {device}: {pub}")
            # pubkey va en el parámetro 'pubkey' cuando step="1"
            self.send_message(device, None, cs.imp_name, pub, step="1")
            return 0, sys.getsizeof(str(pub))

    def intersection_second_step(self, device, cs, _, peer_pubkey):
        with with_log_context(self, cs, "SECOND_STEP", device):
            print(f"[DEBUG][{self.scheme_name}] Step 2 called by {device} with peer pubkey: {peer_pubkey}")
            try:
                # 1) Normalización mínima y segura:
                #    - Híbrido: dict con 'pq' y 'xc' -> pasar tal cual
                #    - No híbrido: normalmente str b64
                if isinstance(peer_pubkey, dict):
                    norm_pub = peer_pubkey
                else:
                    # si el helper ofrece un "decode_public_key", úsalo; si no, pasa el valor como está
                    if hasattr(cs, "decode_public_key"):
                        norm_pub = cs.decode_public_key(peer_pubkey)
                    else:
                        norm_pub = peer_pubkey

                if norm_pub is None:
                    raise ValueError("Peer public key is None after normalization")

                # 2) Encapsular
                ct, sk = cs.encapsulate(norm_pub)
                sk_hex = sk.hex() if isinstance(sk, (bytes, bytearray)) else str(sk)
                print(f"[DEBUG][{self.scheme_name}] Encapsulated key: {sk_hex}")

                # Guarda clave del respondedor
                self.results[f"{self.scheme_name} SharedKey"] = sk_hex
                self.results[f"{self.id}-{device} {self.scheme_name} SharedKey"] = sk_hex

                # 3) Preparar 'data' (ciphertext) para enviar
                if hasattr(cs, "get_ciphertext"):
                    data = cs.get_ciphertext()  # puede ser str b64 o dict (híbrido)
                else:
                    # si el helper ya devuelve el 'ct' listo (dict o bytes), úsalo
                    data = ct
                    if isinstance(data, (bytes, bytearray)):
                        data = base64.b64encode(data).decode("utf-8")

                print(f"[DEBUG][{self.scheme_name}] Step 2 sending ciphertext to {device}: {data}")
                self.send_message(device, data, cs.imp_name, step="2")
                return 0, sys.getsizeof(str(data))

            except Exception as e:
                print(f"[ERROR][{self.scheme_name}] intersection_second_step failed: {e}")
                raise

    def intersection_final_step(self, device, cs, peer_data):
        with with_log_context(self, cs, "FINAL_STEP", device):
            print(f"[DEBUG][{self.scheme_name}] Step 3 called by {device} with peer ciphertext: {peer_data}")
            try:
                # Caso híbrido: peer_data es un dict {"pq": "...", "xc": "..."} -> decapsulate(dict)
                # Caso no híbrido: normalmente str b64 -> decapsulate(str)
                sk = cs.decapsulate(peer_data)

                # Serializa a hex para homogeneizar
                sk_bytes = sk if isinstance(sk, (bytes, bytearray)) else (
                    bytes.fromhex(sk) if isinstance(sk, str) and all(c in "0123456789abcdef" for c in sk.lower()) else
                    (sk.encode("utf-8") if isinstance(sk, str) else bytes(sk))
                )
                sk_hex = sk_bytes.hex()
                print(f"[{self.scheme_name}Handler] Shared key with {device}: {sk_hex}")

                self.results[f"{self.scheme_name} SharedKey"] = sk_hex
                self.results[f"{self.id}-{device} {self.scheme_name} SharedKey"] = sk_hex
                return None, None

            except Exception as e:
                print(f"[ERROR][{self.scheme_name}] intersection_final_step failed: {e}")
                raise
