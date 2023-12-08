import ckb.scw


def test_scw_addr():
    user = ckb.scw.Scw(1)
    addr = user.addr
    assert addr == 'ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40'


def test_dao():
    user = ckb.scw.Dao(1)
    assert user.capacity() == user.capacity_deposit() + user.capacity_prepare()
