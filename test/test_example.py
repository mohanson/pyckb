import pytest
import subprocess


def call(c: str):
    return subprocess.run(c, check=True, shell=True)


def test_addr():
    call('python example/addr.py --prikey 1')


def test_capacity():
    call('python example/capacity.py --addr ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40')


def test_deploy():
    call('python example/deploy.py --prikey 1 --file LICENSE')


@pytest.mark.skip()
def test_faucet():
    call('python example/faucet.py --addr ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40')


def test_redeem():
    call('python example/redeem.py --prikey 1')


def test_txdump():
    call('python example/txdump.py --net testnet --hash 0x123b09a89e65cc9c375dab739c9c921f7067d0b205e563135bb5a1221f8948d9')
