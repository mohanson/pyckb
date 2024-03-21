import argparse
import ckb

# Get the capacity by an address.

parser = argparse.ArgumentParser()
parser.add_argument('addr', type=str, help='address')
args = parser.parse_args()

capacity = int(ckb.rpc.get_cells_capacity({
    'script': ckb.core.address_decode(args.addr).json(),
    'script_type': 'lock',
    'filter': {
        'script_len_range': ['0x0', '0x1']
    }
})['capacity'], 16)
print(capacity / ckb.core.shannon)
