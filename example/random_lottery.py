import ckb
import concurrent.futures
import itertools
import random

ckb.config.current = ckb.config.mainnet
ckb.config.upgrade('http://127.0.0.1:8114')

for _ in itertools.repeat(0):
    acc = ckb.scw.Scw(random.randint(0, ckb.secp256k1.N - 1))
    if acc.capacity() > 0:
        print(acc.prikey)
        break
