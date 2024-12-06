import pyckb
import random


def test_addr():
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
    prikey = pyckb.core.PriKey(1)
    pubkey = prikey.pubkey()
    args = pyckb.core.hash(pubkey.sec())[:20]
    script = pyckb.core.Script(
        pyckb.config.current.script.secp256k1_blake160.code_hash,
        pyckb.config.current.script.secp256k1_blake160.hash_type,
        args
    )
    addr = pyckb.core.address_encode(script)
    assert addr == 'ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40'
    assert pyckb.core.address_decode(addr) == script
    assert script.hash().hex() == '0b1bae4beaf456349c63c3ce67491fc75a1276d7f9eedd7ea84d6a77f9f3f5f7'
    assert pyckb.core.Script.molecule_decode(script.molecule()) == script


def test_block():
    pyckb.config.current = pyckb.config.mainnet
    block_num = random.randint(1, 11333728)
    block_hex = pyckb.rpc.call('get_block_by_number', [hex(block_num), '0x0'])
    block_bin = bytearray.fromhex(block_hex[2:])
    block = pyckb.core.Block.molecule_decode(block_bin)
    assert block.molecule() == block_bin


def test_block_v1():
    pyckb.config.current = pyckb.config.mainnet
    block_num = random.randint(11333729, int(pyckb.rpc.get_tip_block_number(), 16))
    block_hex = pyckb.rpc.call('get_block_by_number', [hex(block_num), '0x0'])
    block_bin = bytearray.fromhex(block_hex[2:])
    block = pyckb.core.BlockV1.molecule_decode(block_bin)
    assert block.molecule() == block_bin


def test_epoch():
    assert pyckb.core.epoch_decode(0x3690138000093) == (147, 312, 873)
    assert pyckb.core.epoch_encode(147, 312, 873) == 0x3690138000093


def test_pubkey():
    # Double checked by https://pyckb.tools/generator
    prikey = pyckb.core.PriKey(1)
    pubkey = prikey.pubkey()
    assert pubkey.x == 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    assert pubkey.y == 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    assert pubkey.sec().hex() == '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    assert pyckb.core.PubKey.sec_decode(pubkey.sec()) == pubkey


def test_pubkey_hash():
    prikey = pyckb.core.PriKey(1)
    pubkey = prikey.pubkey()
    assert pyckb.core.hash(pubkey.sec())[:20].hex() == '75178f34549c5fe9cd1a0c57aebd01e7ddf9249e'


def test_script():
    script = pyckb.core.Script(
        pyckb.config.current.script.secp256k1_blake160.code_hash,
        pyckb.config.current.script.secp256k1_blake160.hash_type,
        bytearray([0x00, 0x01, 0x02, 0x03])
    )
    assert pyckb.core.Script.molecule_decode(script.molecule()) == script


def test_sign():
    prikey = pyckb.core.PriKey(1)
    prikey.sign(bytearray.fromhex('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8'))


def test_witness_args():
    witness_args = pyckb.core.WitnessArgs(
        bytearray([0x00, 0x01, 0x02, 0x03]),
        bytearray([0x00, 0x01, 0x02, 0x03]),
        None,
    )
    assert pyckb.core.WitnessArgs.molecule_decode(witness_args.molecule()) == witness_args
