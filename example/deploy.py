import argparse
import pyckb

# Deploy a script to the chain.

parser = argparse.ArgumentParser()
parser.add_argument('--file', type=str, help='script file')
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

user = pyckb.wallet.Wallet(int(args.prikey, 0))
hole = pyckb.core.Script(
    pyckb.config.current.script.secp256k1_blake160.code_hash,
    pyckb.config.current.script.secp256k1_blake160.hash_type,
    bytearray([0] * 20)
)

with open(args.file, 'rb') as f:
    data = f.read()
    print(f'script.code_hash = 0x{pyckb.core.hash(data).hex()}')
    print(f'script.hash_type = 2(data1)')
    hash = user.script_deploy(hole, data)
    print(f'out_point.hash   = 0x{hash.hex()}')
    print(f'out_point.index  = 0')
    pyckb.rpc.wait(f'0x{hash.hex()}')
