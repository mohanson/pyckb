import ckb.config
import ckb.core
import itertools
import random
import requests
import time

# Doc: https://github.com/nervosnetwork/ckb/tree/develop/rpc


def get_block_by_number(block_number):
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_block_by_number',
        'params': [block_number]
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def get_cells(search_key, order, limit, after):
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_cells',
        'params': [search_key, order, limit, after]
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def get_cells_iter(search_key):
    cursor = None
    limits = 256
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
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def get_current_epoch():
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_current_epoch',
        'params': []
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def get_header(block_hash, verbosity=None):
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_header',
        'params': [block_hash, verbosity]
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def get_header_by_number(block_number, verbosity=None):
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_header_by_number',
        'params': [block_number, verbosity]
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def get_indexer_tip():
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_indexer_tip',
        'params': []
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def get_tip_block_number():
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_tip_block_number',
        'params': []
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def get_tip_header():
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_tip_header',
        'params': []
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def get_transaction(tx_hash, verbosity=None, only_committed=None):
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_transaction',
        'params': [tx_hash, verbosity, only_committed]
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def send_transaction(transaction, outputs_validator=None):
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'send_transaction',
        'params': [transaction, outputs_validator]
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def wait(hash):
    for _ in itertools.repeat(0):
        time.sleep(1)
        r = get_transaction(hash)
        if r['tx_status']['status'] == 'committed':
            break
