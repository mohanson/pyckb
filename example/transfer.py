import argparse
import pyckb

# Transfer ckb to another account. If value is 0, then all assets will be transferred.

parser = argparse.ArgumentParser()
parser.add_argument('--net', type=str, choices=['develop', 'mainnet', 'testnet'], default='develop')
parser.add_argument('--prikey', type=str, help='private key')
parser.add_argument('--to', type=str, help='ckb address')
parser.add_argument('--value', type=float, help='ckb value')
args = parser.parse_args()

if args.net == 'develop':
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
if args.net == 'mainnet':
    pyckb.config.current = pyckb.config.mainnet
if args.net == 'testnet':
    pyckb.config.current = pyckb.config.testnet

user = pyckb.wallet.Wallet(int(args.prikey, 0))
hole = pyckb.core.address_decode(args.to)
if args.value == 0:
    hash = user.transfer_all(hole)
    print(f'0x{hash.hex()}')
    pyckb.rpc.wait(f'0x{hash.hex()}')
if args.value >= 1:
    hash = user.transfer(hole, int(args.value * pyckb.denomination.ckbytes))
    print(f'0x{hash.hex()}')
    pyckb.rpc.wait(f'0x{hash.hex()}')
