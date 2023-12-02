import ckb.config
import ckb.core
import itertools
import random
import requests

# Doc: https://github.com/nervosnetwork/ckb/tree/develop/rpc


def get_cells(search_key, order, limit, after):
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_cells',
        'params': [search_key, order, limit, after]
    })
    return r.json()['result']


if __name__ == '__main__':
    prikey = ckb.core.PriKey(0x0000000000000000000000000000000000000000000000000000000000000001)
    pubkey = prikey.pubkey()
    args = ckb.core.hash(pubkey.pack())[:20].hex()
    script = ckb.core.Script(
        ckb.config.current.scripts.secp256k1_blake160.code_hash,
        ckb.config.current.scripts.secp256k1_blake160.hash_type,
        bytearray.fromhex(args)
    )
    search = {'script': script.json(), 'script_type': 'lock'}
    assert get_cells(search, 'asc', '0xff', None)['objects'] != []


def get_cells_iter(search_key):
    cursor = None
    limits = 8
    for _ in itertools.repeat(0):
        r = get_cells(search_key, 'asc', hex(limits), cursor)
        cursor = r['last_cursor']
        for e in r['objects']:
            yield e
        if len(r['objects']) < limits:
            break


def get_cells_capacity(search_key):
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_cells_capacity',
        'params': [search_key]
    })
    return r.json()['result']


if __name__ == '__main__':
    prikey = ckb.core.PriKey(0x0000000000000000000000000000000000000000000000000000000000000001)
    pubkey = prikey.pubkey()
    args = ckb.core.hash(pubkey.pack())[:20].hex()
    script = ckb.core.Script(
        ckb.config.current.scripts.secp256k1_blake160.code_hash,
        ckb.config.current.scripts.secp256k1_blake160.hash_type,
        bytearray.fromhex(args)
    )
    search = {'script': script.json(), 'script_type': 'lock'}
    assert int(get_cells_capacity(search)['capacity'], 16) >= 0


def get_indexer_tip():
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_indexer_tip',
        'params': []
    })
    return r.json()['result']


if __name__ == '__main__':
    assert int(get_indexer_tip()['block_number'], 16) >= 0


def get_tip_block_number():
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_tip_block_number',
        'params': []
    })
    return r.json()['result']


if __name__ == '__main__':
    assert int(get_tip_block_number(), 16) >= 0


def send_transaction(transaction, outputs_validator):
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'send_transaction',
        'params': [transaction, outputs_validator]
    })
    print(r.json())
    return r.json()['result']
