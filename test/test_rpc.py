import pyckb


def test_get_cells():
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
    prikey = pyckb.core.PriKey(1)
    pubkey = prikey.pubkey()
    args = pyckb.core.hash(pubkey.sec())[:20].hex()
    script = pyckb.core.Script(
        pyckb.config.current.script.secp256k1_blake160.code_hash,
        pyckb.config.current.script.secp256k1_blake160.hash_type,
        bytearray.fromhex(args)
    )
    search = {'script': script.json(), 'script_type': 'lock'}
    assert pyckb.rpc.get_cells(search, 'asc', '0xff', None)['objects'] != []


def test_get_cells_capacity():
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
    prikey = pyckb.core.PriKey(1)
    pubkey = prikey.pubkey()
    args = pyckb.core.hash(pubkey.sec())[:20].hex()
    script = pyckb.core.Script(
        pyckb.config.current.script.secp256k1_blake160.code_hash,
        pyckb.config.current.script.secp256k1_blake160.hash_type,
        bytearray.fromhex(args)
    )
    search = {'script': script.json(), 'script_type': 'lock'}
    assert int(pyckb.rpc.get_cells_capacity(search)['capacity'], 16) >= 0


def test_get_current_epoch():
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
    assert int(pyckb.rpc.get_current_epoch()['number'], 0) >= 0


def test_get_header_by_number():
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
    header_json = pyckb.rpc.get_header_by_number('0x1')
    header = pyckb.core.Header.json_decode(header_json)
    assert header.raw.number == 1
    assert header.hash() == bytearray.fromhex(header_json['hash'][2:])


def test_get_indexer_tip():
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
    assert int(pyckb.rpc.get_indexer_tip()['block_number'], 16) >= 0


def test_get_tip_block_numner():
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
    assert int(pyckb.rpc.get_tip_block_number(), 16) >= 0
