import ckb.config
import random
import requests

# Doc: https://github.com/nervosnetwork/ckb/tree/develop/rpc


def get_tip_block_number():
    r = requests.post(ckb.config.current.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'get_tip_block_number',
        'params': []
    })
    return int(r.json()['result'], 16)


if __name__ == '__main__':
    assert get_tip_block_number() >= 0
