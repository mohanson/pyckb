import pyckb.secp256k1
import secrets


def sign(prikey: pyckb.secp256k1.Fr, m: pyckb.secp256k1.Fr) -> tuple[pyckb.secp256k1.Fr, pyckb.secp256k1.Fr, int]:
    # https://www.secg.org/sec1-v2.pdf
    # 4.1.3 Signing Operation
    for _ in range(64):
        k = pyckb.secp256k1.Fr(max(1, secrets.randbelow(pyckb.secp256k1.N)))
        R = pyckb.secp256k1.G * k
        r = pyckb.secp256k1.Fr(R.x.n)
        if r.n == 0:
            continue
        s = (m + prikey * r) / k
        if s.n == 0:
            continue
        v = 0
        if R.y.n & 1 == 1:
            v |= 1
        if R.x.n >= pyckb.secp256k1.N:
            v |= 2
        return r, s, v
    raise Exception('unreachable')


def verify(pubkey: pyckb.secp256k1.Pt, m: pyckb.secp256k1.Fr, r: pyckb.secp256k1.Fr, s: pyckb.secp256k1.Fr) -> bool:
    # https://www.secg.org/sec1-v2.pdf
    # 4.1.4 Verifying Operation
    a = m / s
    b = r / s
    R = pyckb.secp256k1.G * a + pubkey * b
    assert R != pyckb.secp256k1.I
    return r == pyckb.secp256k1.Fr(R.x.n)


def pubkey(m: pyckb.secp256k1.Fr, r: pyckb.secp256k1.Fr, s: pyckb.secp256k1.Fr, v: int) -> pyckb.secp256k1.Pt:
    # https://www.secg.org/sec1-v2.pdf
    # 4.1.6 Public Key Recovery Operation
    assert v in [0, 1, 2, 3]
    if v & 2 == 0:
        x = pyckb.secp256k1.Fq(r.n)
    else:
        x = pyckb.secp256k1.Fq(r.n + pyckb.secp256k1.N)
    z = x * x * x + pyckb.secp256k1.A * x + pyckb.secp256k1.B
    y = z ** ((pyckb.secp256k1.P + 1) // 4)
    if v & 1 != y.n & 1:
        y = -y
    R = pyckb.secp256k1.Pt(x, y)
    return (R * s - pyckb.secp256k1.G * m) / r
