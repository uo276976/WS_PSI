import json
import time

from Crypto.handlers.CAOPEHandler import CAOPEHandler
from Crypto.handlers.DomainPSIHandler import DomainPSIHandler
from Crypto.handlers.OPEHandler import OPEHandler
from Crypto.handlers.DHHandler import DHHandler
from Crypto.handlers.KyberHandler import KyberHandler
from Crypto.handlers.FrodoKEMHandler import FrodoKEMHandler
from Crypto.handlers.ClassicMcElieceHandler import ClassicMcElieceHandler
from Crypto.handlers.PQCKEMHandlers import KEMHandler
from Crypto.helpers.BFVHelper import BFVHelper
from Crypto.helpers.CryptoImplementation import CryptoImplementation
from Crypto.helpers.DamgardJurikHandler import DamgardJurikHelper
from Crypto.helpers.PaillierHandler import PaillierHelper
from Crypto.helpers.DiffieHellmanHelper import DiffieHellmanHelper
from Crypto.helpers.FrodoKEMHelper import FrodoKEMHelper
from Crypto.helpers.ClassicMcElieceHelper import ClassicMcElieceHelper
from Crypto.helpers.PQCKEMHelpers import BIKEHelper, HQCHelper, NTRUHelper, P256Helper, X25519Helper, HybridKyberX25519Helper, KyberHelper
from Logs import Logs
from Logs.Logs import ThreadData
from Network.PriorityExecutor import PriorityExecutor
from Network.collections.DbConstants import VERSION, TEST_ROUNDS


# Priorities
# 0: Intersection first step
# 1: Intersection second step
# 2: Intersection final step
# 1 and 2 will be executed first to stop consuming memory on the queue
class JSONHandler:
    def __init__(self, id, my_data, domain, devices, results, new_peer_function, device_type="Unknown"):
        self.CSHandlers = {
            "Paillier": PaillierHelper(),
            "DamgardJurik": DamgardJurikHelper(),
            "BFV": BFVHelper(),
            "Diffie-Hellman": DiffieHellmanHelper(),
            "Kyber": KyberHelper(),
            "FrodoKEM": FrodoKEMHelper(),
            "ClassicMcEliece": ClassicMcElieceHelper(),
            "BIKE": BIKEHelper(),
            "HQC": HQCHelper(),
            "NTRU": NTRUHelper(),
            "P256": P256Helper(),
            "X25519": X25519Helper(),
            "HybridKyberX25519": HybridKyberX25519Helper(),
        }

        # PSI
        self.OPEHandler = OPEHandler(id, my_data, domain, devices, results)
        self.CAOPEHandler = CAOPEHandler(id, my_data, domain, devices, results)
        self.domainPSIHandler = DomainPSIHandler(id, my_data, domain, devices, results)

        # NIKE handlers "clásicos"
        self.DHHandler = DHHandler(id, my_data, domain, devices, results)
        self.ClassicMcElieceHandler = ClassicMcElieceHandler(id, my_data, domain, devices, results)
        self.KyberHandler = KyberHandler(id, my_data, domain, devices, results)
        self.FrodoKEMHandler = FrodoKEMHandler(id, my_data, domain, devices, results)

        # KEM genérico
        self.KEMHandlers = {
            "BIKE": KEMHandler(id, my_data, domain, devices, results, "BIKE-L1"),
            "HQC": KEMHandler(id, my_data, domain, devices, results, "HQC-128"),
            "NTRU": KEMHandler(id, my_data, domain, devices, results, "sntrup761"),
            "P256": KEMHandler(id, my_data, domain, devices, results, "P-256"),
            "X25519": KEMHandler(id, my_data, domain, devices, results, "X25519"),
            "HybridKyberX25519": KEMHandler(id, my_data, domain, devices, results, "Hybrid-Kyber-X25519"),
        }

        # NIKEHandlers indexados por nombre (string)
        self.NIKEHandlers = {
            "Diffie-Hellman": self.DHHandler,
            "Kyber": self.KyberHandler,
            "FrodoKEM": self.FrodoKEMHandler,
            "ClassicMcEliece": self.ClassicMcElieceHandler,
            "BIKE": self.KEMHandlers["BIKE"],
            "HQC": self.KEMHandlers["HQC"],
            "NTRU": self.KEMHandlers["NTRU"],
            "P256": self.KEMHandlers["P256"],
            "X25519": self.KEMHandlers["X25519"],
            "HybridKyberX25519": self.KEMHandlers["HybridKyberX25519"],
        }

        self.id = id
        self.devices = devices
        self.executor = PriorityExecutor(max_workers=10)
        self.new_peer = new_peer_function
        self.device_type = device_type

    def test_launcher(self, device, category_filter=None):
        print(f"[TEST_LAUNCHER] Device: {device}, Filter: {category_filter}")
        for name, cs_helper in self.CSHandlers.items():
            cs_impl = CryptoImplementation.from_string(name)
            if category_filter and cs_impl.category.lower() != category_filter.lower():
                continue

            for _ in range(TEST_ROUNDS):
                if cs_impl.category == "PSI-Domain":
                    self.executor.submit(0, self.domainPSIHandler.intersection_first_step, device, cs_helper)
                elif cs_impl.category == "OPE":
                    self.executor.submit(0, self.OPEHandler.intersection_first_step, device, cs_helper)
                elif cs_impl.category == "PSI-CA":
                    self.executor.submit(0, self.CAOPEHandler.intersection_first_step, device, cs_helper)
                elif cs_impl.category == "NIKE":
                    handler = self.NIKEHandlers.get(cs_impl.name)
                    if handler:
                        self.executor.submit(0, handler.intersection_first_step, device, cs_helper)

    def genkeys(self, cs, bit_length=None, domain=None):
        crypto_impl = CryptoImplementation.from_string(cs)
        start_time = time.time()
        thread_data = ThreadData()
        Logs.start_logging(thread_data)

        device_type = self.device_type

        cs_helper = self.CSHandlers.get(crypto_impl.name)
        if cs_helper is None:
            Logs.stop_logging(thread_data)
            return

        if domain is not None:
            cs_helper.generate_keys(bit_length=bit_length, domain=domain)
        else:
            cs_helper.generate_keys(bit_length=bit_length)

        end_time = time.time()
        Logs.stop_logging(thread_data)

        print(f"Key generation - {cs} - Time: {end_time - start_time:.4f}s")

    def start_intersection(self, device, scheme, type, rounds) -> str:
        normalized = scheme.replace("-", "").replace(" ", "")
        crypto_impl = CryptoImplementation.from_string(normalized)

        if crypto_impl is None:
            return f"Invalid scheme: {scheme}"

        cs = self.CSHandlers.get(crypto_impl.name)
        if cs is None:
            return f"Invalid scheme: {scheme}"

        category_lower = crypto_impl.category.lower()
        type_lower = type.lower()

        for _ in range(int(rounds)):
            if category_lower == "ope" and type_lower == "ope":
                self.executor.submit(0, self.OPEHandler.intersection_first_step, device, cs)
            elif category_lower == "psi-ca" and type_lower == "psi-ca":
                self.executor.submit(0, self.CAOPEHandler.intersection_first_step, device, cs)
            elif category_lower == "psi-domain" and type_lower == "psi-domain":
                self.executor.submit(0, self.domainPSIHandler.intersection_first_step, device, cs)
            elif category_lower == "nike" and type_lower == "nike":
                handler = self.NIKEHandlers.get(crypto_impl.name)
                if handler:
                    self.executor.submit(0, handler.intersection_first_step, device, cs)
                else:
                    return f"No handler found for {scheme}"
            else:
                return f"Incompatible scheme {scheme} with type {type}"

        return f"Intersection with {device} - {scheme} - {type} - Rounds: {rounds} - Task started, check logs"

    def handle_message(self, message: str):
        try:
            msg = json.loads(message)
        except json.JSONDecodeError:
            print("Received non-JSON message:", message)
            return

        step   = msg.get('step')
        impl   = msg.get('implementation')
        peer   = msg.get('peer')
        data   = msg.get('data')
        pubkey = msg.get('pubkey')

        print(f"[DEBUG] handle_message called with step: {step}, impl: {impl}, peer: {peer}")

        if peer not in self.devices:
            detected_type = msg.get("device_type") or self.device_type or "Unknown"
            self.new_peer(peer, time.strftime("%H:%M:%S", time.localtime()), device_type=detected_type)

        crypto_impl = CryptoImplementation.from_string(impl.replace("-", "").replace(" ", ""))
        if crypto_impl.category != "NIKE":
            print(f"[DEBUG] Skipping non-NIKE scheme: {crypto_impl.name}")
            return

        handler = self.NIKEHandlers.get(crypto_impl.name)
        cs      = self.CSHandlers.get(crypto_impl.name)
        print(f"[DEBUG] Handler found: {bool(handler)}, CS found: {bool(cs)}")
        if not handler or cs is None:
            print(f"[ERROR] No handler or CS helper for NIKE scheme {crypto_impl.name}")
            return

        if step == "1":
            print(f"[DEBUG] Submitting intersection_second_step for {impl}")
            self.executor.submit(1, handler.intersection_second_step, peer, cs, None, pubkey)
        elif step == "2":
            print(f"[DEBUG] Submitting intersection_final_step for {impl}")
            self.executor.submit(2, handler.intersection_final_step, peer, cs, data)
        elif step == "F":
            print(f"[DEBUG] Submitting final step (F) for {impl}")
            self.executor.submit(2, handler.intersection_final_step, peer, cs, pubkey)
        else:
            print(f"[ERROR] Unknown step {step} for NIKE scheme {crypto_impl.name}")

    def handle_intersection_second_step(self, message):
        crypto_impl = CryptoImplementation.from_string(message['implementation'])
        cs = self.CSHandlers.get(crypto_impl.name)
        if cs is None:
            raise Exception("Invalid scheme: " + message['implementation'])

        peer   = message['peer']
        data   = message['data']
        pubkey = message['pubkey']

        if crypto_impl.category == "PSI-CA":
            self.executor.submit(1, self.CAOPEHandler.intersection_second_step, peer, cs, data, pubkey)
        elif crypto_impl.category == "OPE":
            self.executor.submit(1, self.OPEHandler.intersection_second_step, peer, cs, data, pubkey)
        elif crypto_impl.category == "NIKE":
            handler = self.NIKEHandlers.get(crypto_impl.name)
            if handler:
                self.executor.submit(1, handler.intersection_second_step, peer, cs, data, pubkey)
            else:
                print(f"No handler found for NIKE scheme {crypto_impl.name}")
        else:
            self.executor.submit(1, self.domainPSIHandler.intersection_second_step, peer, cs, data, pubkey)

    def handle_intersection_final_step(self, message):
        crypto_impl = CryptoImplementation.from_string(message['implementation'])
        cs = self.CSHandlers.get(crypto_impl.name)
        if cs is None:
            raise Exception("Invalid scheme: " + message['implementation'])

        peer = message['peer']
        data = message['data']

        if crypto_impl.category == "PSI-CA":
            self.executor.submit(2, self.CAOPEHandler.intersection_final_step, peer, cs, data)
        elif crypto_impl.category == "OPE":
            self.executor.submit(2, self.OPEHandler.intersection_final_step, peer, cs, data)
        elif crypto_impl.category == "NIKE":
            handler = self.NIKEHandlers.get(crypto_impl.name)
            if handler:
                self.executor.submit(2, handler.intersection_final_step, peer, cs, data)
            else:
                print(f"No handler found for NIKE scheme {crypto_impl.name}")
        else:
            self.executor.submit(2, self.domainPSIHandler.intersection_final_step, peer, cs, data)
