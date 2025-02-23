import pyckb

# Pyckb provides a unit testing framework to help script developers test their scripts. To use this framework, you need
# to install ckb-debugger first. This example tests an always success script.

dl = pyckb.unittest.Resource()
tx = pyckb.core.Transaction(pyckb.core.RawTransaction(0, [], [], [], [], []), [])
cell_lock = dl.create_cell(0, dl.create_script_in_vain(), None, pyckb.unittest.script_always_success)
cell_i = dl.create_cell(0, dl.create_script_by_data(cell_lock, bytearray()), None, bytearray())
tx.raw.cell_deps.append(dl.create_cell_dep(cell_lock, 0))
tx.raw.inputs.append(dl.create_cell_input(cell_i))
re = pyckb.unittest.Verifier(dl, tx)
re.verify_success()
for e in re.verify():
    print(e.stdout.decode())
