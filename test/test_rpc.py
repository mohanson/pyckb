import ckb


def test_get_cells():
    ckb.config.upgrade('http://127.0.0.1:8114')
    ckb.config.current = ckb.config.develop
    prikey = ckb.core.PriKey(1)
    pubkey = prikey.pubkey()
    args = ckb.core.hash(pubkey.sec())[:20].hex()
    script = ckb.core.Script(
        ckb.config.current.script.secp256k1_blake160.code_hash,
        ckb.config.current.script.secp256k1_blake160.hash_type,
        bytearray.fromhex(args)
    )
    search = {'script': script.json(), 'script_type': 'lock'}
    assert ckb.rpc.get_cells(search, 'asc', '0xff', None)['objects'] != []


def test_get_cells_capacity():
    ckb.config.upgrade('http://127.0.0.1:8114')
    ckb.config.current = ckb.config.develop
    prikey = ckb.core.PriKey(1)
    pubkey = prikey.pubkey()
    args = ckb.core.hash(pubkey.sec())[:20].hex()
    script = ckb.core.Script(
        ckb.config.current.script.secp256k1_blake160.code_hash,
        ckb.config.current.script.secp256k1_blake160.hash_type,
        bytearray.fromhex(args)
    )
    search = {'script': script.json(), 'script_type': 'lock'}
    assert int(ckb.rpc.get_cells_capacity(search)['capacity'], 16) >= 0


def test_get_current_epoch():
    ckb.config.upgrade('http://127.0.0.1:8114')
    ckb.config.current = ckb.config.develop
    assert int(ckb.rpc.get_current_epoch()['number'], 0) >= 0


def test_get_header_by_number():
    ckb.config.upgrade('http://127.0.0.1:8114')
    ckb.config.current = ckb.config.develop
    header_json = ckb.rpc.get_header_by_number('0x1')
    header = ckb.core.Header.json_decode(header_json)
    assert header.raw.number == 1
    assert header.hash() == bytearray.fromhex(header_json['hash'][2:])


def test_get_indexer_tip():
    ckb.config.upgrade('http://127.0.0.1:8114')
    ckb.config.current = ckb.config.develop
    assert int(ckb.rpc.get_indexer_tip()['block_number'], 16) >= 0


def test_get_tip_block_numner():
    ckb.config.upgrade('http://127.0.0.1:8114')
    ckb.config.current = ckb.config.develop
    assert int(ckb.rpc.get_tip_block_number(), 16) >= 0
