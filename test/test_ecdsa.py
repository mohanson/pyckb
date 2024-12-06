import pyckb
import random


def test_sign():
    prikey = pyckb.secp256k1.Fr(random.randint(0, pyckb.secp256k1.N - 1))
    pubkey = pyckb.secp256k1.G * prikey
    m = pyckb.secp256k1.Fr(random.randint(0, pyckb.secp256k1.N - 1))
    r, s, _ = pyckb.ecdsa.sign(prikey, m)
    assert pyckb.ecdsa.verify(pubkey, m, r, s)


def test_pubkey():
    prikey = pyckb.secp256k1.Fr(random.randint(0, pyckb.secp256k1.N - 1))
    pubkey = pyckb.secp256k1.G * prikey
    m = pyckb.secp256k1.Fr(random.randint(0, pyckb.secp256k1.N - 1))
    r, s, v = pyckb.ecdsa.sign(prikey, m)
    assert pyckb.ecdsa.pubkey(m, r, s, v) == pubkey
