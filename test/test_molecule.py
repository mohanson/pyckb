import ckb


def test_bytes():
    a = ckb.molecule.Bytes(bytearray([0x00, 0x01]))
    b = ckb.molecule.Bytes.molecule_read(a.molecule())
    assert a.data == b
