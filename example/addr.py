import argparse
import pyckb

# Calculate address from private key in secp256k1 lock.

parser = argparse.ArgumentParser()
parser.add_argument('--net', type=str, choices=['develop', 'mainnet', 'testnet'], default='develop')
parser.add_argument('--prikey', type=str, help='private key')
args = parser.parse_args()

if args.net == 'develop':
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
if args.net == 'mainnet':
    pyckb.config.current = pyckb.config.mainnet
if args.net == 'testnet':
    pyckb.config.current = pyckb.config.testnet

prikey = pyckb.core.PriKey(int(args.prikey, 0))
pubkey = prikey.pubkey()
args = pyckb.core.hash(pubkey.sec())[:20]
script = pyckb.core.Script(
    pyckb.config.current.script.secp256k1_blake160.code_hash,
    pyckb.config.current.script.secp256k1_blake160.hash_type,
    args
)
addr = pyckb.core.address_encode(script)
print(addr)
