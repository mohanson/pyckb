import ckb


def test_wallet_addr():
    user = ckb.wallet.Wallet(1)
    addr = user.addr
    assert addr == 'ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40'


def test_wallet_transfer():
    user = ckb.wallet.Wallet(1)
    mate = ckb.wallet.Wallet(2)
    capacity = 100 * ckb.core.shannon
    capacity_old = mate.capacity()
    hash = user.transfer(mate.script, capacity)
    ckb.rpc.wait(f'0x{hash.hex()}')
    capacity_new = mate.capacity()
    assert capacity_new - capacity_old == capacity
    hash = mate.transfer_all(user.script)
    ckb.rpc.wait(f'0x{hash.hex()}')
    assert mate.capacity() == 0


def test_wallet_script_deploy():
    user = ckb.wallet.Wallet(1)
    hash = user.script_deploy(user.script, bytearray([0, 1, 2, 3]))
    ckb.rpc.wait(f'0x{hash.hex()}')


def test_wallet_script_deploy_type_id():
    user = ckb.wallet.Wallet(1)
    hash = user.script_deploy_type_id(user.script, bytearray([0, 1, 2, 3]))
    ckb.rpc.wait(f'0x{hash.hex()}')
    out_point = ckb.core.OutPoint(hash, 0)
    hash = user.script_update_type_id(user.script, bytearray([0, 1, 2, 3, 4, 5]), out_point)
    ckb.rpc.wait(f'0x{hash.hex()}')


def test_wallet_dao():
    user = ckb.wallet.Wallet(1)
    hash = user.dao_deposit(200 * ckb.core.shannon)
    ckb.rpc.wait(f'0x{hash.hex()}')
    hash = user.dao_prepare(ckb.core.OutPoint(hash, 0))
    ckb.rpc.wait(f'0x{hash.hex()}')
