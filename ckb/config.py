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
    # https://github.com/nervosnetwork/ckb/wiki/Public-JSON-RPC-nodes
    'url': 'https://mainnet.ckb.dev',
    'scripts': {
        'dao': {
            'code_hash': bytearray.fromhex('82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e'),
            'hash_type': 1,
        },
        'secp256k1_blake160': {
            'code_hash': bytearray.fromhex('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8'),
            'hash_type': 1,
        },
    }
})

testnet = ObjectDict({
    'hrp': 'ckt',
    # https://github.com/nervosnetwork/ckb/wiki/Public-JSON-RPC-nodes
    'url': 'https://testnet.ckb.dev',
    'scripts': {
        'dao': {
            'code_hash': bytearray.fromhex('82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e'),
            'hash_type': 1,
        },
        'secp256k1_blake160': {
            'code_hash': bytearray.fromhex('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8'),
            'hash_type': 1,
        },
    }
})

current = testnet
