import json
import time
import base64
import binascii
from Logs.Logs import ThreadData, start_logging, stop_logging

class IntersectionHandler:
    def __init__(self, id, my_data, domain, devices, results, device_type="Unknown"):
        self.id = id
        self.my_data = my_data
        self.domain = domain
        self.devices = devices
        self.results = results
        self.device_type = device_type
        
        self.thread_data = None
        self.logging_active = False

    def send_message(self, peer, ser_enc_res, implementation,
                 peer_pubkey=None, step=None):
        """
        Send a JSON message for any NIKE or PSI step.
        # Compatible with handlers using with_log_context / log_activity.
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
        
        current_key_size = self.measure_mb(peer_pubkey) if peer_pubkey is not None else 0.0
        current_ciphertext_size = self.measure_mb(ser_enc_res) if ser_enc_res is not None else 0.0

        prev_key = getattr(self, "_max_key_size_mb", 0.0)
        prev_ct = getattr(self, "_max_ciphertext_size_mb", 0.0)

        self._max_key_size_mb = max(prev_key, current_key_size)
        self._max_ciphertext_size_mb = max(prev_ct, current_ciphertext_size)

        if peer_pubkey is not None:
            msg["pubkey"] = peer_pubkey
            msg["key_size_mb"] = self._max_key_size_mb

        if ser_enc_res is not None:
            msg["ciphertext_size_mb"] = self._max_ciphertext_size_mb

        self._last_key_size_mb = current_key_size
        self._last_ciphertext_size_mb = current_ciphertext_size

        # Optional context metadata (if available)
        if hasattr(self, "scheme_name"):
            msg["scheme_name"] = getattr(self, "scheme_name", implementation)
        if hasattr(self, "category"):
            msg["category"] = getattr(self, "category", None)

        # Debug trace
        try:
            from datetime import datetime
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(
                f"[SEND][{ts}] → {peer} | step={step} | impl={implementation} | "
                f"pk={bool(peer_pubkey)}(cur={current_key_size}MB / max={self._max_key_size_mb}MB) | "
                f"ct={bool(ser_enc_res)}(cur={current_ciphertext_size}MB / max={self._max_ciphertext_size_mb}MB)"
            )
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

    def start_persistent_logging(self):
        if not self.logging_active:
            self.thread_data = ThreadData()
            start_logging(self.thread_data)
            self.logging_active = True
            print(f"[LOGGING] Started persistent logging for {self.id} ({self.device_type})")

    def stop_persistent_logging(self):
        if self.logging_active and self.thread_data:
            time.sleep(0.15)
            stop_logging(self.thread_data)
            
            msg = (f"[STOP_LOGGING] Stopped persistent logging for {self.id} "
               f"({self.device_type}) | Avg CPU={self.thread_data.avg_instance_cpu_usage}% "
               f"| Avg RAM={self.thread_data.avg_instance_ram_usage}MB")
            print(msg, flush=True)
            self.logging_active = False

    def measure_mb(self, data):
        """
        Devuelve el tamaño REAL (en MB) de los datos binarios transmitidos.
        Si el contenido está en base64, lo decodifica para obtener el tamaño
        original en bytes. Si no lo está, mide directamente su longitud binaria.
        """
        if data is None:
            return 0.0

        try:
            # Caso 1: bytes reales
            if isinstance(data, (bytes, bytearray)):
                size_bytes = len(data)

            # Caso 2: base64 válido
            elif isinstance(data, str):
                stripped = data.strip()
                try:
                    decoded = base64.b64decode(stripped, validate=True)
                    size_bytes = len(decoded)
                except Exception:
                    # No es base64 → medir el texto bruto (posiblemente JSON)
                    size_bytes = len(stripped.encode("utf-8"))

            # Caso 3: diccionarios o estructuras serializadas
            elif isinstance(data, dict):
                total_bytes = 0
                for k, v in data.items():
                    if any(x in k.lower() for x in ["key", "pub", "ciphertext"]):
                        total_bytes += self.measure_mb(v) * (1024 ** 2)
                if total_bytes == 0:
                    total_bytes = len(json.dumps(data).encode("utf-8"))
                size_bytes = total_bytes

            # Caso 4: entero (poco probable aquí)
            elif isinstance(data, int):
                size_bytes = (data.bit_length() + 7) // 8

            else:
                size_bytes = len(str(data).encode("utf-8"))

        except Exception:
            size_bytes = len(str(data).encode("utf-8"))

        # Convertir a MB
        return round(size_bytes / (1024 ** 2), 6)
        
    def intersection_first_step(self, device, cs):
        raise NotImplementedError

    def intersection_second_step(self, device, cs, peer_data, pubkey):
        raise NotImplementedError

    def intersection_final_step(self, device, cs, peer_data):
        raise NotImplementedError
