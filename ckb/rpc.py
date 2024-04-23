import ckb.config
import ckb.core
import itertools
import random
import requests
import time
import typing

# Doc: https://github.com/nervosnetwork/ckb/tree/develop/rpc


def call(method: str, params: typing.List) -> typing.Any:
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': method,
        'params': params,
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def get_block_by_number(block_number: str) -> typing.Dict:
    return call('get_block_by_number', [block_number])


def get_cells(search_key: typing.Dict, order: str, limit: str, after: str) -> typing.Dict:
    return call('get_cells', [search_key, order, limit, after])


def get_cells_iter(search_key: typing.Dict) -> typing.Generator:
    cursor = None
    limits = 256
    for _ in itertools.repeat(0):
        r = get_cells(search_key, 'asc', hex(limits), cursor)
        cursor = r['last_cursor']
        for e in r['objects']:
            yield e
        if len(r['objects']) < limits:
            break


def get_cells_capacity(search_key: typing.Dict) -> typing.Dict:
    return call('get_cells_capacity', [search_key])


def get_current_epoch() -> typing.Dict[str, typing.Any]:
    return call('get_current_epoch', [])


def get_header(block_hash: str, verbosity: int = None) -> typing.Dict:
    return call('get_header', [block_hash, verbosity])


def get_header_by_number(block_number: str, verbosity: int = None) -> typing.Dict:
    return call('get_header_by_number', [block_number, verbosity])


def get_indexer_tip() -> typing.Dict:
    return call('get_indexer_tip', [])


def get_tip_block_number() -> str:
    return call('get_tip_block_number', [])


def get_tip_header() -> typing.Dict:
    return call('get_tip_header', [])


def get_transaction(tx_hash: str, verbosity: int = None, only_committed: int = None) -> typing.Dict:
    return call('get_transaction', [tx_hash, verbosity, only_committed])


def send_transaction(transaction: typing.Dict, outputs_validator: str = None) -> str:
    return call('send_transaction', [transaction, outputs_validator])


def wait(hash: str):
    for _ in itertools.repeat(0):
        time.sleep(1)
        r = get_transaction(hash)
        if r['tx_status']['status'] == 'committed':
            break
