import itertools
import pyckb.secp256k1
import random
import typing


def sign(prikey: pyckb.secp256k1.Fr, m: pyckb.secp256k1.Fr) -> typing.Tuple[pyckb.secp256k1.Fr, pyckb.secp256k1.Fr, int]:
    # https://www.secg.org/sec1-v2.pdf
    # 4.1.3 Signing Operation
    for _ in itertools.repeat(0):
        k = pyckb.secp256k1.Fr(random.randint(0, pyckb.secp256k1.N - 1))
        R = pyckb.secp256k1.G * k
        r = pyckb.secp256k1.Fr(R.x.x)
        if r.x == 0:
            continue
        s = (m + prikey * r) / k
        if s.x == 0:
            continue
        v = 0
        if R.y.x & 1 == 1:
            v |= 1
        if R.x.x >= pyckb.secp256k1.N:
            v |= 2
        return r, s, v


def verify(pubkey: pyckb.secp256k1.Pt, m: pyckb.secp256k1.Fr, r: pyckb.secp256k1.Fr, s: pyckb.secp256k1.Fr) -> bool:
    # https://www.secg.org/sec1-v2.pdf
    # 4.1.4 Verifying Operation
    u1 = m / s
    u2 = r / s
    x = pyckb.secp256k1.G * u1 + pubkey * u2
    assert x != pyckb.secp256k1.I
    v = pyckb.secp256k1.Fr(x.x.x)
    return v == r


def pubkey(m: pyckb.secp256k1.Fr, r: pyckb.secp256k1.Fr, s: pyckb.secp256k1.Fr, v: int) -> pyckb.secp256k1.Pt:
    # https://www.secg.org/sec1-v2.pdf
    # 4.1.6 Public Key Recovery Operation
    assert v in [0, 1, 2, 3]
    if v & 2 == 0:
        x = pyckb.secp256k1.Fq(r.x)
    else:
        x = pyckb.secp256k1.Fq(r.x + pyckb.secp256k1.N)
    y_y = x * x * x + pyckb.secp256k1.A * x + pyckb.secp256k1.B
    y = y_y ** ((pyckb.secp256k1.P + 1) // 4)
    if v & 1 != y.x & 1:
        y = -y
    R = pyckb.secp256k1.Pt(x, y)
    return (R * s - pyckb.secp256k1.G * m) / r
