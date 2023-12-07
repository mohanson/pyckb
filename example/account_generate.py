import ckb.config
import ckb.core

prikey = ckb.core.PriKey(1)
print(f'prikey = {prikey.molecule_pack().hex()}')
pubkey = prikey.pubkey()
print(f'pubkey = {pubkey.molecule_pack().hex()}')
args = ckb.core.hash(pubkey.molecule_pack())[:20]
print(f'  args = {args.hex()}')
script = ckb.core.Script(
    ckb.config.current.scripts.secp256k1_blake160.code_hash,
    ckb.config.current.scripts.secp256k1_blake160.hash_type,
    args,
)
print(f'  hash = {script.hash().hex()}')
addr = ckb.core.address_encode(script)
print(f'  addr = {addr}')
