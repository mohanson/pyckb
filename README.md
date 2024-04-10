# Python SDK for CKB

Python CKB is an experimental project that aims to provide human-friendly interfaces for common CKB operations. Note that Python CKB is not a complete SDK, but only implements the CKB functions that I am interested in.

Features:

- No third-party dependencies. All code is visible.
- Incredibly simple.

## Installation

```sh
$ python -m pip install pyckb
# or
$ git clone https://github.com/mohanson/pyckb
$ cd pyckb
$ python -m pip install --editable . --config-settings editable_mode=strict
```

## Usage

By default, pyckb is configured on the develop. To switch networks, see `ckb.config`.

**example/addr.py**

Calculate address from private key in secp256k1 lock.

```sh
$ python example/addr.py --prikey 0x0000000000000000000000000000000000000000000000000000000000000001

# ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40
```

**example/capacity.py**

Get the capacity by an address.

```sh
$ python example/capacity.py --addr ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40

# 3523312.39054609
```

**example/deploy.py**

Deploy a script to the chain.

```sh
$ python example/deploy.py --prikey 0x0000000000000000000000000000000000000000000000000000000000000001 --file LICENSE

# script.code_hash = 0x1a124d54d4f37713b8f17fc12142ede488906d4290fbb178d7aad214977814ee
# script.hash_type = 2(data1)
# out_point.hash   = 0x418f60d67ff3e9841a3091c55cb4eb50837602582495931c372fff99f3107f38
# out_point.index  = 0
```

**example/faucet.py**

One faucet to send 300000 CKB to any ckb addresses. Note this only takes effect on the testnet.

```sh
$ python example/faucet.py --addr ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40
```

**example/redeem.py**

Attempt to withdraw all funds from Dao. When running the test case of pyckb by `pytest -v`, a part of ckb will be locked in Dao. Use this script to recover this part of the funds.

```sh
$ python example/redeem.py --prikey 0x0000000000000000000000000000000000000000000000000000000000000001
```

**example/txdump.py**

Dump full transaction data for ckb-debugger to use.

```sh
$ python example/txdump.py --net testnet --hash 0x123b09a89e65cc9c375dab739c9c921f7067d0b205e563135bb5a1221f8948d9
```

## Test

```sh
$ wget https://github.com/nervosnetwork/ckb/releases/download/v0.115.0/ckb_v0.115.0_x86_64-unknown-linux-gnu.tar.gz
$ tar -zxvf ckb_v0.115.0_x86_64-unknown-linux-gnu.tar.gz
$ cd ckb_v0.115.0_x86_64-unknown-linux-gnu/

$ ckb init --chain dev --ba-arg 0x75178f34549c5fe9cd1a0c57aebd01e7ddf9249e --ba-message 0xabcd
$ ckb run --indexer
$ ckb miner

$ pytest -v
```

## License

MIT
