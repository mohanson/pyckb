import random
import requests


class ObjectDict(dict):
    def __getattr__(self, name: str):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value


develop = ObjectDict({
    'hrp': 'ckt',
    'url': 'http://127.0.0.1:8114',
    'script': ObjectDict({
        'dao': ObjectDict({
            'code_hash': bytearray.fromhex('82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e'),
            'hash_type': 1,
            'cell_dep': ObjectDict({
                'out_point': ObjectDict({
                    'tx_hash': bytearray.fromhex('0000000000000000000000000000000000000000000000000000000000000000'),
                    'index': 2,
                }),
                'dep_type': 0,
            })
        }),
        'secp256k1_blake160': ObjectDict({
            'code_hash': bytearray.fromhex('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8'),
            'hash_type': 1,
            'cell_dep': ObjectDict({
                'out_point': ObjectDict({
                    'tx_hash': bytearray.fromhex('0000000000000000000000000000000000000000000000000000000000000000'),
                    'index': 0,
                }),
                'dep_type': 1,
            })
        }),
    })
})

mainnet = ObjectDict({
    'hrp': 'ckb',
    # https://github.com/nervosnetwork/ckb/wiki/Public-JSON-RPC-nodes
    'url': 'https://mainnet.ckb.dev',
    'script': ObjectDict({
        'dao': ObjectDict({
            'code_hash': bytearray.fromhex('82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e'),
            'hash_type': 1,
            'cell_dep': ObjectDict({
                'out_point': ObjectDict({
                    'tx_hash': bytearray.fromhex('e2fb199810d49a4d8beec56718ba2593b665db9d52299a0f9e6e75416d73ff5c'),
                    'index': 2,
                }),
                'dep_type': 0,
            })
        }),
        'secp256k1_blake160': ObjectDict({
            'code_hash': bytearray.fromhex('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8'),
            'hash_type': 1,
            'cell_dep': ObjectDict({
                'out_point': ObjectDict({
                    'tx_hash': bytearray.fromhex('71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c'),
                    'index': 0,
                }),
                'dep_type': 1,
            })
        }),
    })
})

testnet = ObjectDict({
    'hrp': 'ckt',
    # https://github.com/nervosnetwork/ckb/wiki/Public-JSON-RPC-nodes
    'url': 'https://testnet.ckb.dev',
    'script': ObjectDict({
        'dao': ObjectDict({
            'code_hash': bytearray.fromhex('82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e'),
            'hash_type': 1,
            'cell_dep': ObjectDict({
                'out_point': ObjectDict({
                    'tx_hash': bytearray.fromhex('8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f'),
                    'index': 2,
                }),
                'dep_type': 0,
            })
        }),
        'secp256k1_blake160': ObjectDict({
            'code_hash': bytearray.fromhex('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8'),
            'hash_type': 1,
            'cell_dep': ObjectDict({
                'out_point': ObjectDict({
                    'tx_hash': bytearray.fromhex('f8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37'),
                    'index': 0,
                }),
                'dep_type': 1,
            })
        }),
    })
})


def upgrade(url: str):
    r = requests.post(url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_block_by_number',
        'params': ['0x0']
    })
    t = r.json()['result']['transactions']
    develop.url = url
    develop.script.dao.cell_dep.out_point.tx_hash = bytearray.fromhex(t[0]['hash'][2:])
    develop.script.secp256k1_blake160.cell_dep.out_point.tx_hash = bytearray.fromhex(t[1]['hash'][2:])


current = testnet
