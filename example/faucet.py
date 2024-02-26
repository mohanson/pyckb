import argparse
import ckb
import itertools
import random
import requests
import time

# This script generates a random address to request ckb from the faucet, and transfers the obtained ckb to the
# specified user, breaking through the single address limit of the faucet.
#
# https://faucet.nervos.org/

parser = argparse.ArgumentParser()
parser.add_argument('addr', type=str, help='ckb address')
args = parser.parse_args()

kana = ckb.wallet.Wallet(random.randint(0, ckb.secp256k1.N - 1))
resp = requests.post('https://faucet-api.nervos.org/claim_events', json={
    'claim_event': {
        'address_hash': kana.addr,
        'amount': '300000'
    }
})
assert resp.status_code == 200
id = resp.json()['data']['id']

for _ in itertools.repeat(0):
    time.sleep(1)
    resp = requests.get(f'https://faucet-api.nervos.org/claim_events')
    assert resp.status_code == 200
    data = resp.json()['claimEvents']['data']
    data = [e for e in data if e['id'] == id]
    if not data:
        continue
    hash = data[0]['attributes']['txHash']
    if not hash:
        continue
    break

ckb.rpc.wait(hash)
hash = kana.transfer_all(ckb.core.address_decode(args.addr))
ckb.rpc.wait(f'0x{hash.hex()}')
