import ckb

ckb.config.current = ckb.config.develop

# user = ckb.scw.Scw(1)
# for e in user.dao_livecell():
#     print(e, int(e['output']['capacity'], 16) / ckb.core.shannon)

# hash = user.dao_deposit(2000 * ckb.core.shannon)
# print(hash)

# hash = user.dao_prepare(ckb.core.OutPoint(bytearray.fromhex('6a7f00c71f8ff6dcb9787415e2f4f3ab563e0345fe547f99cd1bcc1e616be30b'), 0))
# print(hash)

# out_point = ckb.core.OutPoint(bytearray.fromhex('650a8ac4f7a9d36b09fa23b3902d8219a14bae68052c589ccaee2d957c7cef06'), 0)
# hash = user.dao_extract(out_point)
# print(hash)
