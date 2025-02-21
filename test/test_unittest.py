import pyckb


def test_always_success():
    dl = pyckb.unittest.Resource()
    tx = pyckb.core.Transaction(pyckb.core.RawTransaction(0, [], [], [], [], []), [])
    cell_lock = dl.create_cell(0, dl.create_script_in_vain(), None, pyckb.unittest.script_always_success)
    cell_i = dl.create_cell(0, dl.create_script_by_data(cell_lock, bytearray()), None, bytearray())
    tx.raw.cell_deps.append(dl.create_cell_dep(cell_lock, 0))
    tx.raw.inputs.append(dl.create_cell_input(cell_i))
    ve = pyckb.unittest.Verifier(dl, tx)
    ve.verify_success()


def test_always_failure():
    dl = pyckb.unittest.Resource()
    tx = pyckb.core.Transaction(pyckb.core.RawTransaction(0, [], [], [], [], []), [])
    cell_lock = dl.create_cell(0, dl.create_script_in_vain(), None, pyckb.unittest.script_always_failure)
    cell_i = dl.create_cell(0, dl.create_script_by_data(cell_lock, bytearray()), None, bytearray())
    tx.raw.cell_deps.append(dl.create_cell_dep(cell_lock, 0))
    tx.raw.inputs.append(dl.create_cell_input(cell_i))
    ve = pyckb.unittest.Verifier(dl, tx)
    ve.verify_failure()
