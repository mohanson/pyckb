import pyckb
import secrets


def test_sign():
    prikey = pyckb.secp256k1.Fr(max(1, secrets.randbelow(pyckb.secp256k1.N)))
    pubkey = pyckb.secp256k1.G * prikey
    m = pyckb.secp256k1.Fr(max(1, secrets.randbelow(pyckb.secp256k1.N)))
    r, s, _ = pyckb.ecdsa.sign(prikey, m)
    assert pyckb.ecdsa.verify(pubkey, m, r, s)


def test_pubkey():
    prikey = pyckb.secp256k1.Fr(max(1, secrets.randbelow(pyckb.secp256k1.N)))
    pubkey = pyckb.secp256k1.G * prikey
    m = pyckb.secp256k1.Fr(max(1, secrets.randbelow(pyckb.secp256k1.N)))
    r, s, v = pyckb.ecdsa.sign(prikey, m)
    assert pyckb.ecdsa.pubkey(m, r, s, v) == pubkey
