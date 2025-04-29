class CryptoImplementation:
    entries = {}

    def __init__(self, name, category, *aliases):
        self.name = name
        self.category = category
        for alias in (name,) + aliases:
            CryptoImplementation.entries[alias] = self

    @staticmethod
    def from_string(text):
        return CryptoImplementation.entries.get(text)

    @staticmethod
    def all_schemes():
        # Returns all registered crypto schemes
        return list(set(impl for impl in CryptoImplementation.entries.values()))

    def __repr__(self):
        return f"<CryptoImplementation name={self.name} category={self.category}>"
    