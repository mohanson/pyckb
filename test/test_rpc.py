import ckb.config
import ckb.core
import ckb.rpc


def test_get_cells():
    prikey = ckb.core.PriKey(1)
    pubkey = prikey.pubkey()
    args = ckb.core.hash(pubkey.molecule_pack())[:20].hex()
    script = ckb.core.Script(
        ckb.config.current.scripts.secp256k1_blake160.code_hash,
        ckb.config.current.scripts.secp256k1_blake160.hash_type,
        bytearray.fromhex(args)
    )
    search = {'script': script.json_pack(), 'script_type': 'lock'}
    assert ckb.rpc.get_cells(search, 'asc', '0xff', None)['objects'] != []


def test_get_cells_capacity():
    prikey = ckb.core.PriKey(1)
    pubkey = prikey.pubkey()
    args = ckb.core.hash(pubkey.molecule_pack())[:20].hex()
    script = ckb.core.Script(
        ckb.config.current.scripts.secp256k1_blake160.code_hash,
        ckb.config.current.scripts.secp256k1_blake160.hash_type,
        bytearray.fromhex(args)
    )
    search = {'script': script.json_pack(), 'script_type': 'lock'}
    assert int(ckb.rpc.get_cells_capacity(search)['capacity'], 16) >= 0


def test_get_indexer_tip():
    assert int(ckb.rpc.get_indexer_tip()['block_number'], 16) >= 0


def test_get_tip_block_numner():
    assert int(ckb.rpc.get_tip_block_number(), 16) >= 0
