import ckb

# ckb.config.current = ckb.config.develop

user = ckb.scw.Scw(1)
for e in user.dao_livecell():
    print(e, int(e['output']['capacity'], 16) / ckb.core.shannon)

# hash = user.dao_deposit(2000 * ckb.core.shannon)
# print(hash)

# hash = user.dao_prepare(ckb.core.OutPoint(bytearray.fromhex('6591f51906e8bd33b7040aa8bf85f660fd54582d0e90170984c75f18be50638d'), 0))
# print(hash)
