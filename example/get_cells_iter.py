import ckb.config
import ckb.core
import ckb.rpc
import itertools


def get_cells(search_key):
    cursor = None
    limits = 8
    for _ in itertools.repeat(0):
        r = ckb.rpc.get_cells(search, 'asc', hex(limits), cursor)
        cursor = r['last_cursor']
        for e in r['objects']:
            yield e
        if len(r['objects']) < limits:
            break


prikey = ckb.core.PriKey(0xd5d8fe30c6ab6bfd2c6e0a940299a1e01a9ab6b8a8ed407a00b130e6a51435fc)
pubkey = prikey.pubkey()
args = ckb.core.hash(pubkey.pack())[:20].hex()
script = ckb.core.Script(
    ckb.config.current.scripts.secp256k1_blake160.code_hash,
    ckb.config.current.scripts.secp256k1_blake160.hash_type,
    bytearray.fromhex(args)
)
search = {'script': script.json(), 'script_type': 'lock'}

for e in get_cells(search):
    print(e['out_point'])
