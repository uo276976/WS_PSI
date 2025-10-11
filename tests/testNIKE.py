import unittest
import json
from Crypto.handlers.PQCKEMHandlers import KEMHandler
from Crypto.handlers.DHHandler import DHHandler
from Crypto.handlers.KyberHandler import KyberHandler
from Crypto.handlers.FrodoKEMHandler import FrodoKEMHandler
from Crypto.handlers.ClassicMcElieceHandler import ClassicMcElieceHandler

from Crypto.helpers.PQCKEMHelpers import (
    KyberHelper, NTRUHelper, BIKEHelper, HQCHelper, P256Helper, X25519Helper, HybridKyberX25519Helper
)

from Crypto.helpers.FrodoKEMHelper import FrodoKEMHelper
from Crypto.helpers.ClassicMcElieceHelper import ClassicMcElieceHelper
from Crypto.helpers.DiffieHellmanHelper import DiffieHellmanHelper

class NikeTests(unittest.TestCase):

    def run_protocol(self, handler_cls, helper_cls, scheme_name="Generic"):
        """Ejecuta el protocolo de 3 pasos para un NIKE y compara claves"""
        alice = helper_cls()
        bob = helper_cls()

        handler_a = handler_cls("Alice", {}, "domain", {}, {}, scheme_name)
        handler_b = handler_cls("Bob", {}, "domain", {}, {}, scheme_name)

        # Step 1: Alice envía su pubkey
        _, _ = handler_a.intersection_first_step("Bob", alice)
        pub_a = alice.serialize_public_key()

        # Step 2: Bob responde
        _, _ = handler_b.intersection_second_step("Alice", bob, None, pub_a)
        if hasattr(bob, "get_ciphertext"):   # KEM-based
            ct = bob.get_ciphertext()
        else:
            ct = bob.serialize_public_key()

        # Step 3: Alice finaliza
        handler_a.intersection_final_step("Bob", alice, ct)

        # Bob también termina (para algunos esquemas)
        if isinstance(handler_b, (DHHandler, KyberHandler)):
            handler_b.intersection_final_step("Alice", bob, pub_a if not hasattr(bob, "get_ciphertext") else ct)

        # Validamos que ambos resultados contengan shared key
        self.assertTrue(any("SharedKey" in k for k in handler_a.results))
        self.assertTrue(any("SharedKey" in k for k in handler_b.results))

        k_a = list(handler_a.results.values())[0]
        k_b = list(handler_b.results.values())[0]
        self.assertEqual(k_a, k_b)

    def test_dh(self):
        self.run_protocol(DHHandler, DiffieHellmanHelper, "DH")

    def test_kyber(self):
        self.run_protocol(KyberHandler, KyberHelper, "Kyber")

    def test_frodokem(self):
        self.run_protocol(FrodoKEMHandler, FrodoKEMHelper, "FrodoKEM")

    def test_classic_mceliece(self):
        self.run_protocol(ClassicMcElieceHandler, ClassicMcElieceHelper, "ClassicMcEliece")

    def test_ntru(self):
        self.run_protocol(KEMHandler, NTRUHelper, "NTRU")

    def test_bike(self):
        self.run_protocol(KEMHandler, BIKEHelper, "BIKE")

    def test_hqc(self):
        self.run_protocol(KEMHandler, HQCHelper, "HQC")

    def test_p256(self):
        self.run_protocol(KEMHandler, P256Helper, "P256")

    def test_x25519(self):
        self.run_protocol(KEMHandler, X25519Helper, "X25519")

    def test_hybrid_kyber_x25519(self):
        self.run_protocol(KEMHandler, HybridKyberX25519Helper, "HybridKyberX25519")


if __name__ == "__main__":
    unittest.main()
