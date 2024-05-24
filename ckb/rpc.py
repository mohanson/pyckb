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


def wait(hash: str):
    for _ in itertools.repeat(0):
        time.sleep(1)
        r = get_transaction(hash)
        if r['tx_status']['status'] == 'committed':
            break


def add_node():
    pass


def calculate_dao_field():
    pass


def calculate_dao_maximum_withdraw():
    pass


def clear_banned_addresses():
    pass


def clear_tx_pool():
    pass


def estimate_cycles():
    pass


def generate_block():
    pass


def generate_block_with_template():
    pass


def generate_epochs():
    pass


def get_banned_addresses():
    pass


def get_block():
    pass


def get_block_by_number(block_number: str) -> typing.Dict:
    return call('get_block_by_number', [block_number])


def get_block_economic_state():
    pass


def get_block_filter():
    pass


def get_block_hash():
    pass


def get_block_median_time():
    pass


def get_block_template():
    pass


def get_blockchain_info():
    pass


def get_cells(search_key: typing.Dict, order: str, limit: str, after: str) -> typing.Dict:
    return call('get_cells', [search_key, order, limit, after])


def get_cells_capacity(search_key: typing.Dict) -> typing.Dict:
    return call('get_cells_capacity', [search_key])


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


def get_consensus():
    pass


def get_current_epoch() -> typing.Dict[str, typing.Any]:
    return call('get_current_epoch', [])


def get_deployments_info():
    pass


def get_epoch_by_number():
    pass


def get_fee_rate_statistics():
    pass


def get_fork_block():
    pass


def get_header(block_hash: str, verbosity: int = None) -> typing.Dict:
    return call('get_header', [block_hash, verbosity])


def get_header_by_number(block_number: str, verbosity: int = None) -> typing.Dict:
    return call('get_header_by_number', [block_number, verbosity])


def get_indexer_tip() -> typing.Dict:
    return call('get_indexer_tip', [])


def get_live_cell():
    pass


def get_peers():
    pass


def get_pool_tx_detail_info():
    pass


def get_raw_tx_pool():
    pass


def get_tip_block_number() -> str:
    return call('get_tip_block_number', [])


def get_tip_header() -> typing.Dict:
    return call('get_tip_header', [])


def get_transaction(tx_hash: str, verbosity: int = None, only_committed: int = None) -> typing.Dict:
    return call('get_transaction', [tx_hash, verbosity, only_committed])


def get_transaction_and_witness_proof():
    pass


def get_transaction_proof():
    pass


def get_transactions():
    pass


def jemalloc_profiling_dump():
    pass


def local_node_info():
    pass


def notify_transaction():
    pass


def ping_peers():
    pass


def process_block_without_verify():
    pass


def remove_node():
    pass


def remove_transaction():
    pass


def send_alert():
    pass


def send_transaction(transaction: typing.Dict, outputs_validator: str = None) -> str:
    return call('send_transaction', [transaction, outputs_validator])


def set_ban():
    pass


def set_extra_logger():
    pass


def set_network_active():
    pass


def submit_block():
    pass


def subscribe():
    pass


def sync_state():
    pass


def test_tx_pool_accept():
    pass


def truncate():
    pass


def tx_pool_info():
    pass


def tx_pool_ready():
    pass


def unsubscribe():
    pass


def update_main_logger():
    pass


def verify_transaction_and_witness_proof():
    pass


def verify_transaction_proof():
    pass
