import ckb.config
import ckb.core


def test_pubkey():
    # Double checked by https://ckb.tools/generator
    prikey = ckb.core.PriKey(1)
    pubkey = prikey.pubkey()
    assert pubkey.x == 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    assert pubkey.y == 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    assert pubkey.pack().hex() == '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    assert ckb.core.PubKey.read(pubkey.pack()) == pubkey


def test_pubkey_hash():
    prikey = ckb.core.PriKey(1)
    pubkey = prikey.pubkey()
    assert ckb.core.hash(pubkey.pack())[:20].hex() == '75178f34549c5fe9cd1a0c57aebd01e7ddf9249e'


def test_sign():
    prikey = ckb.core.PriKey(1)
    prikey.sign(bytearray.fromhex('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8'))


def test_addr():
    prikey = ckb.core.PriKey(1)
    pubkey = prikey.pubkey()
    args = ckb.core.hash(pubkey.pack())[:20].hex()
    script = ckb.core.Script(
        ckb.config.current.scripts.secp256k1_blake160.code_hash,
        ckb.config.current.scripts.secp256k1_blake160.hash_type,
        bytearray.fromhex(args)
    )
    addr = ckb.core.address_encode(script)
    assert addr == 'ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40'
    assert ckb.core.address_decode(addr) == script
    assert script.hash().hex() == '0b1bae4beaf456349c63c3ce67491fc75a1276d7f9eedd7ea84d6a77f9f3f5f7'
    assert ckb.core.Script.read(script.pack()) == script