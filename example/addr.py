import argparse
import ckb

# Calculate address from private key in secp256k1 lock.

parser = argparse.ArgumentParser()
parser.add_argument('prikey', type=str, help='private key')
args = parser.parse_args()

prikey = ckb.core.PriKey(int(args.prikey, 0))
pubkey = prikey.pubkey()
args = ckb.core.hash(pubkey.molecule())[:20]
script = ckb.core.Script(
    ckb.config.current.script.secp256k1_blake160.code_hash,
    ckb.config.current.script.secp256k1_blake160.hash_type,
    args
)
addr = ckb.core.address_encode(script)
print(addr)
