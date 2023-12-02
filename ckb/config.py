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
            'cell_dep': {
                'out_point': {
                    'tx_hash': bytearray.fromhex('e2fb199810d49a4d8beec56718ba2593b665db9d52299a0f9e6e75416d73ff5c'),
                    'index': 2,
                },
                'dep_type': 0,
            }
        },
        'secp256k1_blake160': {
            'code_hash': bytearray.fromhex('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8'),
            'hash_type': 1,
            'cell_dep': {
                'out_point': {
                    'tx_hash': bytearray.fromhex('71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c'),
                    'index': 0,
                },
                'dep_type': 1,
            }
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
            'cell_dep': {
                'out_point': {
                    'tx_hash': bytearray.fromhex('8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f'),
                    'index': 2,
                },
                'dep_type': 0,
            }
        },
        'secp256k1_blake160': {
            'code_hash': bytearray.fromhex('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8'),
            'hash_type': 1,
            'cell_dep': {
                'out_point': {
                    'tx_hash': bytearray.fromhex('f8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37'),
                    'index': 0,
                },
                'dep_type': 1,
            }
        },
    }
})

current = testnet
