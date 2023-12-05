import ckb

a = ckb.scw.Scw(1)
b = ckb.scw.Scw(2)

h = a.transfer(b.script, 1000 * ckb.core.shannon)
print(h)
