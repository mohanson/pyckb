class ObjectDict(dict):
    def __getattr__(self, name: str):
        try:
            v = self[name]
            if type(v) == dict:
                return ObjectDict(v)
            else:
                return v
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value


mainnet = ObjectDict({
    'hrp': 'ckb',
    'scripts': {
        'secp256k1_blake160': {
            'code_hash': bytearray.fromhex('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8'),
            'hash_type': 1,
        }
    }
})

testnet = ObjectDict({
    'hrp': 'ckt',
    'scripts': {
        'secp256k1_blake160': {
            'code_hash': bytearray.fromhex('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8'),
            'hash_type': 1,
        }
    }
})

current = testnet
