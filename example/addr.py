import argparse
import ckb

# Calculate the address from a private key.

parser = argparse.ArgumentParser()
parser.add_argument('prikey', type=str, help='private key')
args = parser.parse_args()

base = 10
if args.prikey.startswith('0x'):
    base = 16

prikey = ckb.core.PriKey(int(args.prikey, base))
pubkey = prikey.pubkey()
args = ckb.core.hash(pubkey.molecule())[:20]
script = ckb.core.Script(
    ckb.config.current.script.secp256k1_blake160.code_hash,
    ckb.config.current.script.secp256k1_blake160.hash_type,
    args
)
addr = ckb.core.address_encode(script)
print(addr)
