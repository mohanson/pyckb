import ckb.config
import ckb.core
import ckb.rpc

prikey = ckb.core.PriKey(0x0000000000000000000000000000000000000000000000000000000000000001)
pubkey = prikey.pubkey()
args = ckb.core.hash(pubkey.pack())[:20].hex()
script = ckb.core.Script(
    ckb.config.current.scripts.secp256k1_blake160.code_hash,
    ckb.config.current.scripts.secp256k1_blake160.hash_type,
    bytearray.fromhex(args)
)
search = {'script': script.json(), 'script_type': 'lock'}

capacity_all = 0
capacity_dao = 0
for e in ckb.rpc.get_cells_iter(search):
    capacity_all += int(e['output']['capacity'], 16)
    if e['output']['type']:
        if bytearray.fromhex(e['output']['type']['code_hash'][2:]) == ckb.config.current.scripts.dao.code_hash:
            capacity_dao += int(e['output']['capacity'], 16)

assert capacity_all == int(ckb.rpc.get_cells_capacity(search)['capacity'], 16)
print(f'all: {capacity_all / 100000000}')
print(f'dao: {capacity_dao / 100000000}')
