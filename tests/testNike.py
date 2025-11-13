import unittest
import json
from Crypto.handlers.PQCKEMHandlers import KEMHandler
from Crypto.handlers.DiffieHellmanHandler import DiffieHellmanHandler
from Crypto.handlers.KyberHandler import KyberHandler
from Crypto.handlers.FrodoKEMHandler import FrodoKEMHandler
from Crypto.handlers.ClassicMcElieceHandler import ClassicMcElieceHandler
from Crypto.handlers.P384Handler import P384Handler
from Crypto.handlers.Secp256k1Handler import Secp256k1Handler
from Crypto.handlers.X448Handler import X448Handler
from Crypto.handlers.RSAHandler import RSAHandler
from Crypto.handlers.HybridKEMHandler import HybridKEMHandler

from Crypto.helpers.PQCKEMHelpers import (
    KyberHelper, SNTRUPHelper, BIKEHelper, HQCHelper, P256Helper, X25519Helper, HybridKyberX25519Helper
)
from Crypto.helpers.FrodoKEMHelper import FrodoKEMHelper
from Crypto.helpers.ClassicMcElieceHelper import ClassicMcElieceHelper
from Crypto.helpers.DiffieHellmanHelper import DiffieHellmanHelper, DiffieHellman8192Helper
from Crypto.helpers.P384Helper import P384Helper
from Crypto.helpers.Secp256k1Helper import Secp256k1Helper
from Crypto.helpers.X448Helper import X448Helper
from Crypto.helpers.RSAHelper import RSAHelper

class NikeTests(unittest.TestCase):

    def run_protocol(self, handler_cls, helper_cls, scheme_name="Generic"):
        """Ejecuta el protocolo de 3 pasos para un NIKE y compara claves"""
        alice = helper_cls()
        bob = helper_cls()

        handler_a = handler_cls("Alice", {}, "domain", {}, {}, device_type="TEST")
        handler_b = handler_cls("Bob", {}, "domain", {}, {}, device_type="TEST")

       # Paso 1: A → B
        _, _ = handler_a.intersection_first_step("Bob", alice)
        pub_a = alice.serialize_public_key()

        # Paso 2: B → A
        _, _ = handler_b.intersection_second_step("Alice", bob, None, pub_a)
        ct = bob.get_ciphertext() if hasattr(bob, "get_ciphertext") else bob.serialize_public_key()

        # Paso 3: A termina
        handler_a.intersection_final_step("Bob", alice, ct)

        # Paso 3: B también termina si aplica
        if hasattr(handler_b, "intersection_final_step"):
            handler_b.intersection_final_step("Alice", bob, pub_a)

        # Validamos que ambos resultados contengan shared key
        self.assertTrue(handler_a.results, "Alice has no results")
        self.assertTrue(handler_b.results, "Bob has no results")
        self.assertTrue(any("SharedKey" in key for key in handler_a.results.keys()))
        self.assertTrue(any("SharedKey" in key for key in handler_b.results.keys()))

        k_a = list(handler_a.results.values())[0]
        k_b = list(handler_b.results.values())[0]
        self.assertEqual(k_a, k_b)

    def test_dh(self):
        self.run_protocol(DiffieHellmanHandler, DiffieHellmanHelper, "Diffie-Hellman")
        
    def test_dh8192(self):
        self.run_protocol(DiffieHellmanHandler, DiffieHellman8192Helper, "Diffie-Hellman-8192")

    def test_kyber(self):
        self.run_protocol(KyberHandler, KyberHelper, "Kyber")

    def test_frodokem(self):
        self.run_protocol(FrodoKEMHandler, FrodoKEMHelper, "FrodoKEM")

    def test_classic_mceliece(self):
        self.run_protocol(ClassicMcElieceHandler, ClassicMcElieceHelper, "ClassicMcEliece")

    def test_sntrup(self):
        self.run_protocol(KEMHandler, SNTRUPHelper, "sntrup761")

    def test_bike(self):
        self.run_protocol(KEMHandler, BIKEHelper, "BIKE-L1")

    def test_hqc(self):
        self.run_protocol(KEMHandler, HQCHelper, "HQC-192")

    def test_p256(self):
        self.run_protocol(KEMHandler, P256Helper, "P-256")
    
    def test_p384(self):
        self.run_protocol(P384Handler, P384Helper, "P-384")

    def test_x25519(self):
        self.run_protocol(KEMHandler, X25519Helper, "X25519")
        
    def test_x448(self):
        self.run_protocol(X448Handler, X448Helper, "X448")
    
    def test_secp256k1(self):
        self.run_protocol(Secp256k1Handler, Secp256k1Helper, "secp256k1")
        
    def test_rsa(self):
        self.run_protocol(RSAHandler, RSAHelper, "RSA")

    def test_hybrid_kyber_x25519(self):
        self.run_protocol(HybridKEMHandler, HybridKyberX25519Helper, "Hybrid-Kyber-X25519")


if __name__ == "__main__":
    unittest.main()
