# Python SDK for CKB

Python CKB is an experimental project that aims to provide human-friendly interfaces for common CKB operations. Note that Python CKB is not a complete SDK, but only implements the CKB functions that I am interested in.

Features:

- No third-party dependencies. All code is visible.
- Incredibly simple.

## Installation

```sh
$ python -m pip install pyckb
```

## Usage

By default, pyckb is configured on the testnet. To switch networks, see `ckb.config`.

**example/deploy.py**

Deploy a script to the chain.

```sh
$ python example/deploy.py LICENSE

script.code_hash = 0x1a124d54d4f37713b8f17fc12142ede488906d4290fbb178d7aad214977814ee
script.hash_type = 2(data1)
out_point.hash   = 0x418f60d67ff3e9841a3091c55cb4eb50837602582495931c372fff99f3107f38
out_point.index  = 0
```

**example/faucet.py**

One faucet to send 300000 CKB to any ckb addresses. The script execution takes 2 blocks, which is about 20 seconds.

```sh
$ python example/faucet.py ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40
```

**example/redeem.py**

Attempt to withdraw all funds from Dao. When running the test case of pyckb by `pytest -v`, a part of ckb will be locked in Dao. Use this script to recover this part of the funds.

```sh
$ python example/redeem.py
```

**example/txdump.py**

Dump full transaction data for [ckb-debugger](https://github.com/nervosnetwork/ckb-standalone-debugger) to use.

```sh
$ python example/txdump.py -x 0x123b09a89e65cc9c375dab739c9c921f7067d0b205e563135bb5a1221f8948d9
```

## License

MIT
