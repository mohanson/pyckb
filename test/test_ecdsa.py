import ckb
import random


def test_sign():
    prikey = ckb.secp256k1.Fr(random.randint(0, ckb.secp256k1.N - 1))
    pubkey = ckb.secp256k1.G * prikey
    m = ckb.secp256k1.Fr(random.randint(0, ckb.secp256k1.N - 1))
    r, s, _ = ckb.ecdsa.sign(prikey, m)
    assert ckb.ecdsa.verify(pubkey, m, r, s)


def test_pubkey():
    prikey = ckb.secp256k1.Fr(random.randint(0, ckb.secp256k1.N - 1))
    pubkey = ckb.secp256k1.G * prikey
    m = ckb.secp256k1.Fr(random.randint(0, ckb.secp256k1.N - 1))
    r, s, v = ckb.ecdsa.sign(prikey, m)
    assert ckb.ecdsa.pubkey(m, r, s, v) == pubkey
