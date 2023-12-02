import ckb.config
import ckb.core

prikey = ckb.core.PriKey(0x0000000000000000000000000000000000000000000000000000000000000001)
print(f'prikey = {prikey.pack().hex()}')
pubkey = prikey.pubkey()
print(f'pubkey = {pubkey.pack().hex()}')
args = ckb.core.hash(pubkey.pack())[:20]
print(f'  args = {args.hex()}')
script = ckb.core.Script(
    ckb.config.current.scripts.secp256k1_blake160.code_hash,
    ckb.config.current.scripts.secp256k1_blake160.hash_type,
    args,
)
print(f'  hash = {script.hash().hex()}')
addr = ckb.core.address_encode(script)
print(f'  addr = {addr}')
