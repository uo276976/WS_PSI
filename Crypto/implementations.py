from Crypto.helpers.CryptoImplementation import CryptoImplementation

# PSI-CA schemes
CryptoImplementation("Paillier", "PSI-CA", "Paillier OPE", "Paillier_OPE", "Paillier PSI-CA OPE")
CryptoImplementation("Damgard-Jurik", "PSI-CA", "DamgardJurik", "DamgardJurik OPE", "Damgard-Jurik_OPE", "Damgard-Jurik PSI-CA OPE")
CryptoImplementation("CAOPE", "PSI-CA")

# PSI-Domain schemes
CryptoImplementation("DomainPSI", "PSI-Domain")

# OPE schemes
CryptoImplementation("BFV", "OPE", "BFV_OPE", "BFV OPE")

# NIKE schemes
CryptoImplementation("Diffie-Hellman", "NIKE", "DH", "DiffieHellman", "Diffie Hellman")
CryptoImplementation("Kyber", "NIKE", "KYBER")
CryptoImplementation("ClassicMcEliece", "NIKE", "McEliece")
CryptoImplementation("FrodoKEM", "NIKE", "Frodo", "frodo")
CryptoImplementation("sntrup761", "NIKE", "sntrup761")
CryptoImplementation("BIKE-L1", "NIKE", "BIKE")
CryptoImplementation("HQC-192", "NIKE", "HQC")
CryptoImplementation("X25519", "NIKE")
CryptoImplementation("P-256", "NIKE", "P256")
CryptoImplementation("Hybrid-Kyber-X25519", "NIKE", "HybridKyberX25519")
CryptoImplementation("Diffie-Hellman-8192", "NIKE", "Diffie-Hellman8192", "DiffieHellman8192", "DH8192", "DH-8192")
CryptoImplementation("P-384", "NIKE", "P384")
CryptoImplementation("secp256k1", "NIKE", "Secp-256k1", "Secp256k1", "SECP256k1")
CryptoImplementation("X448", "NIKE")
CryptoImplementation("RSA", "NIKE")