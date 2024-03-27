import argparse
import ckb

# Get the capacity by an address.

parser = argparse.ArgumentParser()
parser.add_argument('--net', type=str, choices=['develop', 'mainnet', 'testnet'], default='testnet')
parser.add_argument('addr', type=str, help='address')
args = parser.parse_args()

if args.net == 'develop':
    ckb.config.upgrade('http://127.0.0.1:8114')
    ckb.config.current = ckb.config.develop
if args.net == 'mainnet':
    ckb.config.current = ckb.config.mainnet
if args.net == 'testnet':
    ckb.config.current = ckb.config.testnet

capacity = int(ckb.rpc.get_cells_capacity({
    'script': ckb.core.address_decode(args.addr).json(),
    'script_type': 'lock',
    'filter': {
        'script_len_range': ['0x0', '0x1']
    }
})['capacity'], 16)
print(capacity / ckb.core.shannon)
