import argparse
import pyckb

# Get the capacity by an address.

parser = argparse.ArgumentParser()
parser.add_argument('--addr', type=str, help='address')
parser.add_argument('--net', type=str, choices=['develop', 'mainnet', 'testnet'], default='develop')
args = parser.parse_args()

if args.net == 'develop':
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
if args.net == 'mainnet':
    pyckb.config.current = pyckb.config.mainnet
if args.net == 'testnet':
    pyckb.config.current = pyckb.config.testnet

capacity = int(pyckb.rpc.get_cells_capacity({
    'script': pyckb.core.address_decode(args.addr).json(),
    'script_type': 'lock',
    'filter': {
        'script_len_range': ['0x0', '0x1']
    }
})['capacity'], 16)
print(capacity / pyckb.denomination.ckbytes)
