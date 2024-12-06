import pyckb


def test_wallet_addr():
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
    user = pyckb.wallet.Wallet(1)
    addr = user.addr
    assert addr == 'ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40'


def test_wallet_transfer():
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
    user = pyckb.wallet.Wallet(1)
    mate = pyckb.wallet.Wallet(2)
    capacity = 100 * pyckb.denomination.ckbytes
    capacity_old = mate.capacity()
    hash = user.transfer(mate.script, capacity)
    pyckb.rpc.wait(f'0x{hash.hex()}')
    capacity_new = mate.capacity()
    assert capacity_new - capacity_old == capacity
    hash = mate.transfer_all(user.script)
    pyckb.rpc.wait(f'0x{hash.hex()}')
    assert mate.capacity() == 0


def test_wallet_script_deploy():
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
    user = pyckb.wallet.Wallet(1)
    hash = user.script_deploy(user.script, bytearray([0, 1, 2, 3]))
    pyckb.rpc.wait(f'0x{hash.hex()}')


def test_wallet_script_deploy_type_id():
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
    user = pyckb.wallet.Wallet(1)
    hash = user.script_deploy_type_id(user.script, bytearray([0, 1, 2, 3]))
    pyckb.rpc.wait(f'0x{hash.hex()}')
    out_point = pyckb.core.OutPoint(hash, 0)
    hash = user.script_update_type_id(user.script, bytearray([0, 1, 2, 3, 4, 5]), out_point)
    pyckb.rpc.wait(f'0x{hash.hex()}')


def test_wallet_dao():
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
    user = pyckb.wallet.Wallet(1)
    hash = user.dao_deposit(200 * pyckb.denomination.ckbytes)
    pyckb.rpc.wait(f'0x{hash.hex()}')
    hash = user.dao_prepare(pyckb.core.OutPoint(hash, 0))
    pyckb.rpc.wait(f'0x{hash.hex()}')
