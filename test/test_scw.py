import ckb


def test_scw_addr():
    user = ckb.scw.Scw(1)
    addr = user.addr
    assert addr == 'ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40'


def test_scw_transfer():
    user = ckb.scw.Scw(1)
    mate = ckb.scw.Scw(2)
    capacity = 100 * ckb.core.shannon
    capacity_old = mate.capacity()
    ckb.rpc.wait(user.transfer(mate.script, capacity))
    capacity_new = mate.capacity()
    assert capacity_new - capacity_old == capacity
    ckb.rpc.wait(mate.transfer_all(user.script))
    assert mate.capacity() == 0


def test_scw_script_deploy():
    user = ckb.scw.Scw(1)
    ckb.rpc.wait(user.script_deploy(user.script, bytearray([0, 1, 2, 3])))


def test_scw_script_deploy_type_id():
    user = ckb.scw.Scw(1)
    hash = user.script_deploy_type_id(user.script, bytearray([0, 1, 2, 3]))
    ckb.rpc.wait(hash)
    out_point = ckb.core.OutPoint(bytearray.fromhex(hash[2:]), 0)
    hash = user.script_update_type_id(user.script, bytearray([0, 1, 2, 3, 4, 5]), out_point)
    ckb.rpc.wait(hash)


def test_scw_dao():
    user = ckb.scw.Scw(1)
    hash = user.dao_deposit(200 * ckb.core.shannon)
    ckb.rpc.wait(hash)
    hash = user.dao_prepare(ckb.core.OutPoint(bytearray.fromhex(hash[2:]), 0))
    ckb.rpc.wait(hash)
