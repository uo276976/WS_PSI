from Crypto.helpers.CryptoImplementation import CryptoImplementation

# PSI-CA schemes
CryptoImplementation("Paillier", "PSI-CA", "Paillier OPE", "Paillier_OPE", "Paillier PSI-CA OPE")
CryptoImplementation("DamgardJurik", "PSI-CA", "Damgard-Jurik", "DamgardJurik OPE", "Damgard-Jurik_OPE", "Damgard-Jurik PSI-CA OPE")
CryptoImplementation("CAOPE", "PSI-CA")

# PSI-Domain schemes
CryptoImplementation("DomainPSI", "PSI-Domain")

# OPE schemes
CryptoImplementation("BFV", "OPE", "BFV_OPE", "BFV OPE")

# NIKE schemes
CryptoImplementation("Diffie-Hellman", "NIKE", "DH")
CryptoImplementation("CSIDH", "NIKE")
CryptoImplementation("Kyber", "NIKE")
#CryptoImplementation("NewHope", "NIKE")
CryptoImplementation("ClassicMcEliece", "NIKE")
CryptoImplementation("FrodoKEM", "NIKE")
