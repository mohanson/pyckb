import argparse
import ckb

# Deploy a script to the chain.

parser = argparse.ArgumentParser()
parser.add_argument('--file', type=str, help='script file')
parser.add_argument('--net', type=str, choices=['develop', 'mainnet', 'testnet'], default='develop')
parser.add_argument('--prikey', type=str, help='private key')
args = parser.parse_args()

if args.net == 'develop':
    ckb.config.upgrade('http://127.0.0.1:8114')
    ckb.config.current = ckb.config.develop
if args.net == 'mainnet':
    ckb.config.current = ckb.config.mainnet
if args.net == 'testnet':
    ckb.config.current = ckb.config.testnet

user = ckb.wallet.Wallet(int(args.prikey, 0))
hole = ckb.core.Script(
    ckb.config.current.script.secp256k1_blake160.code_hash,
    ckb.config.current.script.secp256k1_blake160.hash_type,
    bytearray([0] * 20)
)

with open(args.file, 'rb') as f:
    data = f.read()
    print(f'script.code_hash = 0x{ckb.core.hash(data).hex()}')
    print(f'script.hash_type = 2(data1)')
    hash = user.script_deploy(hole, data)
    print(f'out_point.hash   = 0x{hash.hex()}')
    print(f'out_point.index  = 0')
    ckb.rpc.wait(f'0x{hash.hex()}')
