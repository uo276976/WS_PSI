import json
import time

from Crypto.handlers.CAOPEHandler import CAOPEHandler
from Crypto.handlers.DomainPSIHandler import DomainPSIHandler
from Crypto.handlers.OPEHandler import OPEHandler
from Crypto.handlers.DiffieHellmanHandler import DiffieHellmanHandler
from Crypto.handlers.KyberHandler import KyberHandler
from Crypto.handlers.FrodoKEMHandler import FrodoKEMHandler
from Crypto.handlers.ClassicMcElieceHandler import ClassicMcElieceHandler
from Crypto.handlers.PQCKEMHandlers import KEMHandler
from Crypto.handlers.HybridKEMHandler import HybridKEMHandler
from Crypto.handlers.P384Handler import P384Handler
from Crypto.handlers.Secp256k1Handler import Secp256k1Handler
from Crypto.handlers.X448Handler import X448Handler
from Crypto.handlers.RSAHandler import RSAHandler

from Crypto.helpers.BFVHelper import BFVHelper
from Crypto.helpers.CryptoImplementation import CryptoImplementation
from Crypto.helpers.DamgardJurikHandler import DamgardJurikHelper
from Crypto.helpers.PaillierHandler import PaillierHelper
from Crypto.helpers.DiffieHellmanHelper import DiffieHellmanHelper, DiffieHellman8192Helper
from Crypto.helpers.FrodoKEMHelper import FrodoKEMHelper
from Crypto.helpers.ClassicMcElieceHelper import ClassicMcElieceHelper
from Crypto.helpers.P384Helper import P384Helper
from Crypto.helpers.Secp256k1Helper import Secp256k1Helper
from Crypto.helpers.X448Helper import X448Helper
from Crypto.helpers.RSAHelper import RSAHelper

from Crypto.helpers.PQCKEMHelpers import BIKEHelper, HQCHelper, SNTRUPHelper, P256Helper, X25519Helper, HybridKyberX25519Helper, KyberHelper
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
        self.device_type = device_type
        
        self.CSHandlers = {
            "Paillier": PaillierHelper(),
            "Damgard-Jurik": DamgardJurikHelper(),
            "BFV": BFVHelper(),
            "Diffie-Hellman": DiffieHellmanHelper(),
            "Kyber": KyberHelper(),
            "FrodoKEM": FrodoKEMHelper(),
            "ClassicMcEliece": ClassicMcElieceHelper(),
            "BIKE-L1": BIKEHelper(),
            "HQC-192": HQCHelper(),
            "sntrup761": SNTRUPHelper(),
            "P-256": P256Helper(),
            "X25519": X25519Helper(), 
            "Diffie-Hellman-8192": DiffieHellman8192Helper(),
            "P-384": P384Helper(),
            "secp256k1": Secp256k1Helper(),
            "X448": X448Helper(),
            "RSA": RSAHelper(),
            "Hybrid-Kyber-X25519": HybridKyberX25519Helper(),
        }

        # PSI
        self.OPEHandler = OPEHandler(id, my_data, domain, devices, results, device_type=self.device_type)
        self.CAOPEHandler = CAOPEHandler(id, my_data, domain, devices, results, device_type=self.device_type)
        self.domainPSIHandler = DomainPSIHandler(id, my_data, domain, devices, results, device_type=self.device_type)

        # NIKE handlers "clásicos"
        self.DiffieHellmanHandler = DiffieHellmanHandler(id, my_data, domain, devices, results, device_type=self.device_type)
        self.ClassicMcElieceHandler = ClassicMcElieceHandler(id, my_data, domain, devices, results, device_type=self.device_type)
        self.KyberHandler = KyberHandler(id, my_data, domain, devices, results, device_type=self.device_type)
        self.FrodoKEMHandler = FrodoKEMHandler(id, my_data, domain, devices, results, device_type=self.device_type)
        
        self.P384Handler = P384Handler(id, my_data, domain, devices, results, device_type=self.device_type)
        self.Secp256k1Handler = Secp256k1Handler(id, my_data, domain, devices, results, device_type=self.device_type)
        self.X448Handler = X448Handler(id, my_data, domain, devices, results, device_type=self.device_type)
        self.RSAHandler = RSAHandler(id, my_data, domain, devices, results, device_type=self.device_type)
        self.HybridKEMHandler = HybridKEMHandler(id, my_data, domain, devices, results, device_type=self.device_type)

        # KEM genérico
        self.KEMHandlers = {
            "BIKE-L1": KEMHandler(id, my_data, domain, devices, results, "BIKE-L1", device_type=self.device_type),
            "HQC-192": KEMHandler(id, my_data, domain, devices, results, "HQC-192", device_type=self.device_type),
            "sntrup761": KEMHandler(id, my_data, domain, devices, results, "sntrup761", device_type=self.device_type),
            "P-256": KEMHandler(id, my_data, domain, devices, results, "P-256", device_type=self.device_type),
            "X25519": KEMHandler(id, my_data, domain, devices, results, "X25519", device_type=self.device_type),
        }

        # NIKEHandlers indexados por nombre
        self.NIKEHandlers = {
            "Diffie-Hellman": self.DiffieHellmanHandler,
            "Kyber": self.KyberHandler,
            "FrodoKEM": self.FrodoKEMHandler,
            "ClassicMcEliece": self.ClassicMcElieceHandler,
            "BIKE-L1": self.KEMHandlers["BIKE-L1"],
            "HQC-192": self.KEMHandlers["HQC-192"],
            "sntrup761": self.KEMHandlers["sntrup761"],
            "P-256": self.KEMHandlers["P-256"],
            "X25519": self.KEMHandlers["X25519"],
            "Hybrid-Kyber-X25519": self.HybridKEMHandler,
            "Diffie-Hellman-8192": self.DiffieHellmanHandler,
            "P-384": self.P384Handler,
            "secp256k1": self.Secp256k1Handler,
            "X448": self.X448Handler,
            "RSA": self.RSAHandler
        }

        self.id = id
        self.devices = devices
        self.executor = PriorityExecutor(max_workers=10)
        self.new_peer = new_peer_function

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
            setattr(cs_helper, "category", crypto_impl.category)
            setattr(cs_helper, "imp_name", crypto_impl.name)
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
        scheme_map = {
            "DiffieHellman": "Diffie-Hellman",
            "DH": "Diffie-Hellman",
            "HybridKyber_X25519": "Hybrid-Kyber-X25519",
            "HybridKyber-X25519": "Hybrid-Kyber-X25519",
            "Hybrid Kyber X25519": "Hybrid-Kyber-X25519",
            "Paillier_OPE": "Paillier",
            "DamgardJurik_OPE": "Damgard-Jurik",
            "Classic McEliece": "ClassicMcEliece",
            "McEliece": "ClassicMcEliece",
            "Frodo": "FrodoKEM",
        }

        scheme_canon = scheme_map.get(scheme, scheme)
        crypto_impl = CryptoImplementation.from_string(scheme_canon)
        if not crypto_impl:
            return f"Invalid scheme: {scheme}"

        cs = self.CSHandlers.get(crypto_impl.name)
        if not cs:
            return f"No CS helper found for {crypto_impl.name}"

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
        
        crypto_impl = CryptoImplementation.from_string(impl)
        if not crypto_impl:
            print(f"[WARN] Unknown crypto implementation: {impl}")
            return

        category = crypto_impl.category or "Unknown"

        handler = None
        cs = self.CSHandlers.get(crypto_impl.name)

        if category == "NIKE":
            handler = self.NIKEHandlers.get(crypto_impl.name)
        elif category == "PSI-CA":
            handler = self.CAOPEHandler
        elif category == "OPE":
            handler = self.OPEHandler
        elif category == "PSI-Domain":
            handler = self.domainPSIHandler

        print(f"[DEBUG] Category: {category} | Handler found: {bool(handler)} | CS found: {bool(cs)}")

        if not handler or cs is None:
            print(f"[ERROR] No handler or CS helper for scheme {crypto_impl.name} ({category})")
            return

        # Handle steps for all categories
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
            print(f"[ERROR] Unknown step {step} for scheme {crypto_impl.name} ({category})")

    def handle_intersection_second_step(self, message):
        crypto_impl = CryptoImplementation.from_string(message.get("implementation"))
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
        crypto_impl = CryptoImplementation.from_string(message.get("implementation"))
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
