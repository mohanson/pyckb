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

**example/faucet.py**

One faucet to send 300000 CKB to any ckb addresses. The script execution takes 2 blocks, which is about 20 seconds.

```sh
$ python example/faucet.py ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40
```
