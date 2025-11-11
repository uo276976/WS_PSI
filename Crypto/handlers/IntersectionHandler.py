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
        
        key_size_mb = self.measure_mb(peer_pubkey) if peer_pubkey is not None else 0.0

        if peer_pubkey is not None:
            msg["pubkey"] = peer_pubkey
            msg["key_size_mb"] = key_size_mb

        # Save for later Firebase logging
        self._last_key_size_mb = key_size_mb

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
        Calcula el tamaño real (en MB) del contenido binario de una clave o mensaje,
        intentando descontar el overhead de codificación (Base64, JSON, etc.).
        """
        if data is None:
            return 0.0

        size_bytes = 0

        try:
            # Caso 1: bytes reales
            if isinstance(data, (bytes, bytearray)):
                size_bytes = len(data)

            # Caso 2: string (Base64 o JSON)
            elif isinstance(data, str):
                stripped = data.strip()

                if len(stripped) % 4 == 0:
                    try:
                        decoded = base64.b64decode(stripped, validate=True)
                        size_bytes = len(decoded)
                    except binascii.Error:
                        size_bytes = len(stripped.encode("utf-8"))
                else:
                    size_bytes = len(stripped.encode("utf-8"))

            # Caso 3: dict o estructura
            elif isinstance(data, dict):
                b64_field = None
                for k, v in data.items():
                    if any(x in k.lower() for x in ["key", "pub"]):
                        b64_field = v
                        break
                if b64_field:
                    try:
                        decoded = base64.b64decode(b64_field, validate=True)
                        size_bytes = len(decoded)
                    except Exception:
                        size_bytes = len(str(b64_field).encode("utf-8"))
                else:
                    size_bytes = len(json.dumps(data).encode("utf-8"))

            # Caso 4: enteros
            elif isinstance(data, int):
                size_bytes = (data.bit_length() + 7) // 8

            # Caso 5: fallback genérico
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
