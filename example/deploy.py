import argparse
import ckb

# Deploy a script to the chain.

parser = argparse.ArgumentParser()
parser.add_argument('file', type=str, help='script file')
args = parser.parse_args()

user = ckb.wallet.Wallet(1)
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
