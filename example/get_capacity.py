import ckb.config
import ckb.core
import ckb.rpc

prikey = ckb.core.PriKey(1)
pubkey = prikey.pubkey()
args = ckb.core.hash(pubkey.molecule_pack())[:20].hex()
script = ckb.core.Script(
    ckb.config.current.scripts.secp256k1_blake160.code_hash,
    ckb.config.current.scripts.secp256k1_blake160.hash_type,
    bytearray.fromhex(args)
)
search = {'script': script.json_pack(), 'script_type': 'lock', 'with_data': False}

capacity_all = 0
capacity_dao = 0
capacity_who = 0
for e in ckb.rpc.get_cells_iter(search):
    capacity_all += int(e['output']['capacity'], 16)
    if e['output']['type']:
        if bytearray.fromhex(e['output']['type']['code_hash'][2:]) == ckb.config.current.scripts.dao.code_hash:
            capacity_dao += int(e['output']['capacity'], 16)
        else:
            capacity_who += int(e['output']['capacity'], 16)

assert capacity_all == int(ckb.rpc.get_cells_capacity(search)['capacity'], 16)
print(f'all: {capacity_all / 100000000}')
print(f'dao: {capacity_dao / 100000000}')
print(f'???: {capacity_who / 100000000}')
