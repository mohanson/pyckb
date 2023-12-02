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


def get_indexer_tip():
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_indexer_tip',
        'params': []
    })
    return r.json()['result']


def get_tip_block_number():
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_tip_block_number',
        'params': []
    })
    return r.json()['result']


def send_transaction(transaction, outputs_validator):
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'send_transaction',
        'params': [transaction, outputs_validator]
    })
    return r.json()['result']
