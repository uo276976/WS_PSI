import json
import time

from Crypto.handlers.CAOPEHandler import CAOPEHandler
from Crypto.handlers.DomainPSIHandler import DomainPSIHandler
from Crypto.handlers.OPEHandler import OPEHandler
from Crypto.handlers.DHHandler import DHHandler
from Crypto.handlers.CSIDHHandler import CSIDHHandler
from Crypto.handlers.KyberHandler import KyberHandler
#from Crypto.handlers.NewHopeHandler import NewHopeHandler
from Crypto.handlers.FrodoKEMHandler import FrodoKEMHandler
from Crypto.handlers.ClassicMcElieceHandler import ClassicMcElieceHandler
from Crypto.helpers.BFVHelper import BFVHelper
from Crypto.helpers.CryptoImplementation import CryptoImplementation
from Crypto.helpers.DamgardJurikHandler import DamgardJurikHelper
from Crypto.helpers.PaillierHandler import PaillierHelper
from Crypto.helpers.DiffieHellmanHelper import DiffieHellmanHelper
from Crypto.helpers.CSIDHHelper import CSIDHHelper
from Crypto.helpers.KyberHelper import KyberHelper
#from Crypto.helpers.NewHopeHelper import NewHopeHelper
from Crypto.helpers.FrodoKEMHelper import FrodoKEMHelper
from Crypto.helpers.ClassicMcElieceHelper import ClassicMcElieceHelper
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
    def __init__(self, id, my_data, domain, devices, results, new_peer_function):
        # Crypto System (CS) Helpers
        self.CSHandlers = {
            CryptoImplementation.from_string("Paillier"): PaillierHelper(),
            CryptoImplementation.from_string("DamgardJurik"): DamgardJurikHelper(),
            CryptoImplementation.from_string("BFV"): BFVHelper(),
            CryptoImplementation.from_string("Diffie-Hellman"): DiffieHellmanHelper(),
            CryptoImplementation.from_string("CSIDH"): CSIDHHelper(),
            CryptoImplementation.from_string("Kyber"): KyberHelper(),
            #CryptoImplementation.from_string("NewHope"): NewHopeHelper(),
            CryptoImplementation.from_string("FrodoKEM"): FrodoKEMHelper(),
            CryptoImplementation.from_string("ClassicMcEliece"): ClassicMcElieceHelper(),
        }

        # Handlers for PSI operations
        self.OPEHandler = OPEHandler(id, my_data, domain, devices, results)
        self.CAOPEHandler = CAOPEHandler(id, my_data, domain, devices, results)
        self.domainPSIHandler = DomainPSIHandler(id, my_data, domain, devices, results)

        # Handlers for NIKEs
        self.DHHandler = DHHandler(id, my_data, domain, devices, results)
        self.CSIDHHandler = CSIDHHandler(id, my_data, domain, devices, results)
        self.KyberHandler = KyberHandler(id, my_data, domain, devices, results)
        #self.NewHopeHandler = NewHopeHandler(id, my_data, domain, devices, results)
        self.FrodoKEMHandler = FrodoKEMHandler(id, my_data, domain, devices, results)
        self.ClassicMcElieceHandler = ClassicMcElieceHandler(id, my_data, domain, devices, results)
                
        self.NIKEHandlers = {
            "Diffie-Hellman": self.DHHandler,
            "CSIDH": self.CSIDHHandler,
            "Kyber": self.KyberHandler,
            "FrodoKEM": self.FrodoKEMHandler,
            "ClassicMcEliece": self.ClassicMcElieceHandler
        }

        # General setup
        self.id = id
        self.devices = devices
        self.executor = PriorityExecutor(max_workers=10)
        self.new_peer = new_peer_function

    def test_launcher(self, device, category_filter=None):
        print(f"[TEST_LAUNCHER] Device: {device}, Filter: {category_filter}")
        for cs_impl, cs_helper in self.CSHandlers.items():
            if category_filter and cs_impl.category != category_filter:
                continue  # Skip if not in the desired category
            
            for _ in range(TEST_ROUNDS):
                if cs_impl.category == "PSI-Domain":
                    self.executor.submit(0, self.domainPSIHandler.intersection_first_step, device, cs_helper)
                elif cs_impl.category == "OPE":
                    self.executor.submit(0, self.OPEHandler.intersection_first_step, device, cs_helper)
                elif cs_impl.category == "PSI-CA":
                    self.executor.submit(0, self.CAOPEHandler.intersection_first_step, device, cs_helper)
                elif cs_impl.category == "NIKE":
                    handler = getattr(self, f"{cs_impl.name.replace('-', '').replace(' ', '')}Handler", None)
                    if handler:
                        self.executor.submit(0, handler.intersection_first_step, device, cs_helper)

    def genkeys(self, cs, bit_length=None, domain=None):
        crypto_impl = CryptoImplementation.from_string(cs)
        start_time = time.time()
        thread_data = ThreadData()
        Logs.start_logging(thread_data)
        
        device_info = self.devices.get(self.id, {})
        device_type = device_info.get("type", "Unknown")

        cs_helper = self.CSHandlers[crypto_impl]
        if domain is not None:
            cs_helper.generate_keys(bit_length=bit_length, domain=domain)
        else:
            cs_helper.generate_keys(bit_length=bit_length)

        end_time = time.time()
        Logs.stop_logging(thread_data)

        print(f"Key generation - {cs} - Time: {end_time - start_time:.4f}s")

        Logs.log_activity(
            thread_data,
            activity_code="INTERSECTION_FINAL_STEP",
            duration=end_time - start_time,
            version=VERSION,
            node_id=self.id,
            scheme=cs_helper.imp_name,
            category=crypto_impl.category,
            device_type=device_type
        )

    def start_intersection(self, device, scheme, type, rounds) -> str:
        crypto_impl = CryptoImplementation.from_string(scheme)
        if crypto_impl not in self.CSHandlers:
            return "Invalid scheme: " + scheme

        cs = self.CSHandlers[crypto_impl]
        for _ in range(int(rounds)):
            if crypto_impl.category == "OPE" and type == "OPE":
                self.executor.submit(0, self.OPEHandler.intersection_first_step, device, cs)
            elif crypto_impl.category == "PSI-CA" and type == "PSI-CA":
                self.executor.submit(0, self.CAOPEHandler.intersection_first_step, device, cs)
            elif crypto_impl.category == "PSI-Domain" and type == "PSI-Domain":
                self.executor.submit(0, self.domainPSIHandler.intersection_first_step, device, cs)
            elif crypto_impl.category == "NIKE" and type == "NIKE":
                handler = self.NIKEHandlers.get(scheme)
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

        step = msg.get('step')
        impl = msg.get('implementation')
        peer = msg.get('peer')
        data = msg.get('data')
        pubkey = msg.get('pubkey')

        # register peer if new
        if peer not in self.devices:
            self.new_peer(peer, time.strftime("%H:%M:%S", time.localtime()))

        crypto_impl = CryptoImplementation.from_string(impl)
        if crypto_impl.category != "NIKE":
            return  # fall back to PSI/OPE handlers

        handler = self.NIKEHandlers.get(crypto_impl.name)
        cs = self.CSHandlers.get(crypto_impl)
        if not handler or cs is None:
            print(f"No handler or CS helper for NIKE scheme {crypto_impl.name}")
            return

        if step == "1":
            # Peer has sent us their pubkey → compute & reply
            self.executor.submit(
                1,
                handler.intersection_second_step,
                peer,
                cs,
                None,
                pubkey
            )
        elif step == "2":
            # Peer has sent back ciphertext (or final DH pubkey) → finalize
            self.executor.submit(
                2,
                handler.intersection_final_step,
                peer,
                cs,
                data
            )
        else:
            print(f"Unknown step {step} for NIKE scheme {crypto_impl.name}")

    def handle_intersection_second_step(self, message):
        crypto_impl = CryptoImplementation.from_string(message['implementation'])
        if crypto_impl not in self.CSHandlers:
            raise Exception("Invalid scheme: " + message['implementation'])

        cs = self.CSHandlers[crypto_impl]
        peer = message['peer']
        data = message['data']
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
        else:  # PSI-Domain
            self.executor.submit(1, self.domainPSIHandler.intersection_second_step, peer, cs, data, pubkey)

    def handle_intersection_final_step(self, message):
        crypto_impl = CryptoImplementation.from_string(message['implementation'])
        if crypto_impl not in self.CSHandlers:
            raise Exception("Invalid scheme: " + message['implementation'])

        cs = self.CSHandlers[crypto_impl]
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
        else:  # PSI-Domain
            self.executor.submit(2, self.domainPSIHandler.intersection_final_step, peer, cs, data)

