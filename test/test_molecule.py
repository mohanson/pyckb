import ckb


def test_bytenn():
    a = ckb.molecule.Bytenn(bytearray([0x00, 0x01]))
    b = ckb.molecule.Bytenn.molecule_read(a.molecule())
    assert a.data == b
