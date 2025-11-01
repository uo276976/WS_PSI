class CryptoImplementation:
    entries = {}

    def __init__(self, name, category, *aliases):
        self.name = name
        self.category = category
        for alias in (name,) + aliases:
            CryptoImplementation.entries[alias] = self

    @staticmethod
    def from_string(text):
        if not text:
            return None
        text = text.strip()

        impl = CryptoImplementation.entries.get(text)
        if impl:
            return impl

        variants = {
            text.replace("-", "").replace(" ", ""),
            text.lower(),
            text.lower().replace("-", "").replace(" ", ""),
            text.upper(),
            text.upper().replace("-", "").replace(" ", "")
        }
        for v in variants:
            if v in CryptoImplementation.entries:
                return CryptoImplementation.entries[v]

        return None

    @staticmethod
    def all_schemes():
        # Returns all registered crypto schemes
        return list(set(impl for impl in CryptoImplementation.entries.values()))

    def __repr__(self):
        return f"<CryptoImplementation name={self.name} category={self.category}>"
    