import ckb.bech32
import ckb.config
import ckb.molecule
import ckb.secp256k1
import hashlib
import io
import json
import random
import typing


def hash(data: bytearray):
    return bytearray(hashlib.blake2b(data, digest_size=32, person=b'ckb-default-hash').digest())


class PriKey:
    def __init__(self, n: int):
        self.n = n

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.n == other.n
        return a

    @staticmethod
    def read(data: bytearray):
        assert len(data) == 32
        return Prikey(int.from_bytes(data, byteorder='big'))

    def pack(self):
        return bytearray(self.n.to_bytes(32, byteorder='big'))

    def json(self):
        return {
            'n': f'0x{self.n:064x}'
        }

    def pubkey(self):
        pubkey = ckb.secp256k1.G * ckb.secp256k1.Fr(self.n)
        return PubKey(pubkey.x.x, pubkey.y.x)

    def sign(self, data: bytearray):
        assert len(data) == 32
        m = ckb.secp256k1.Fr(int.from_bytes(data))
        while True:
            k = ckb.secp256k1.Fr(random.randint(0, ckb.secp256k1.N - 1))
            R = ckb.secp256k1.G * k
            r = ckb.secp256k1.Fr(R.x.x)
            if r.x == 0:
                continue
            s = (m + ckb.secp256k1.Fr(self.n) * r) / k
            if s.x == 0:
                continue
            v = 0
            if R.y.x & 1 == 1:
                v |= 1
            if R.x.x >= ckb.secp256k1.N:
                v |= 2
            if s.x > ckb.secp256k1.N // 2:
                s.x = ckb.secp256k1.N - s.x
                v ^= 1
            return bytearray(r.x.to_bytes(32)) + bytearray(s.x.to_bytes(32)) + bytearray([v])


class PubKey:
    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.x == other.x
        b = self.y == other.y
        return a and b

    @staticmethod
    def read(data: bytearray):
        assert len(data) == 33
        o = data[0]
        x = int.from_bytes(data[1:33], byteorder='big')
        y_x_y = x * x * x + ckb.secp256k1.A.x * x + ckb.secp256k1.B.x
        y = pow(y_x_y, (ckb.secp256k1.P + 1) // 4, ckb.secp256k1.P)
        if y & 1 != o - 2:
            return PubKey(x, -y % ckb.secp256k1.P)
        else:
            return PubKey(x, +y)

    def pack(self):
        r = bytearray()
        if self.y & 1 == 0:
            r.append(0x02)
        else:
            r.append(0x03)
        r.extend(self.x.to_bytes(32, byteorder='big'))
        return r

    def json(self):
        return {
            'x': f'0x{self.x:064x}',
            'y': f'0x{self.y:064x}'
        }


if __name__ == '__main__':
    # Double checked by https://ckb.tools/generator
    prikey = PriKey(0x0000000000000000000000000000000000000000000000000000000000000001)
    pubkey = prikey.pubkey()
    assert pubkey.x == 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    assert pubkey.y == 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    assert pubkey.pack().hex() == '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    assert PubKey.read(pubkey.pack()) == pubkey
    assert hash(pubkey.pack())[:20].hex() == '75178f34549c5fe9cd1a0c57aebd01e7ddf9249e'


if __name__ == '__main__':
    prikey = PriKey(0x0000000000000000000000000000000000000000000000000000000000000001)
    sig = prikey.sign(bytearray.fromhex('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8'))
    print(sig.hex())


class Script:
    def __init__(self, code_hash: bytearray, hash_type: int, args: bytearray):
        assert len(code_hash) == 32
        assert hash_type < 3  # 0 => data, 1 => type, 2 => data1
        self.code_hash = code_hash
        self.hash_type = hash_type
        self.args = args

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.code_hash == other.code_hash
        b = self.hash_type == other.hash_type
        c = self.args == other.args
        return a and b and c

    @staticmethod
    def read(data: bytearray):
        result = ckb.molecule.Dynvec.read(data)
        code_hash = result[0]
        hash_type = int(result[1][0])
        args = ckb.molecule.Bytenn.read(result[2])
        return Script(code_hash, hash_type, args)

    def pack(self):
        return ckb.molecule.Dynvec([
            ckb.molecule.Byte32(self.code_hash),
            ckb.molecule.Byte(self.hash_type),
            ckb.molecule.Bytenn(self.args)
        ]).pack()

    def json(self):
        return {
            'code_hash': f'0x{self.code_hash.hex()}',
            'hash_type': {
                0: 'data',
                1: 'type',
                2: 'data1'
            }[self.hash_type],
            'args': f'0x{self.args.hex()}',
        }


def address_encode(script: Script):
    # See: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md
    # See: https://github.com/rev-chaos/ckb-address-demo/blob/master/ckb_addr_test.py
    payload = bytearray()
    payload.append(0x00)
    # Append secp256k1 code hash
    payload.extend(script.code_hash)
    payload.append(script.hash_type)
    payload.extend(script.args)
    return ckb.bech32.bech32_encode(
        ckb.config.current.hrp,
        ckb.bech32.convertbits(payload, 8, 5),
        ckb.bech32.Encoding.BECH32M
    )


def address_decode(address: str):
    _, data, _ = ckb.bech32.bech32_decode(address)
    data = bytearray(ckb.bech32.convertbits(data, 5, 8, False))
    code_hash = data[1:33]
    hash_type = data[33]
    args = data[34:]
    return Script(code_hash, hash_type, args)


if __name__ == '__main__':
    prikey = PriKey(0x0000000000000000000000000000000000000000000000000000000000000001)
    pubkey = prikey.pubkey()
    args = hash(pubkey.pack())[:20].hex()
    script = Script(
        ckb.config.current.scripts.secp256k1_blake160.code_hash,
        ckb.config.current.scripts.secp256k1_blake160.hash_type,
        bytearray.fromhex(args)
    )
    addr = address_encode(script)
    assert addr == 'ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40'
    assert address_decode(addr) == script
    assert hash(script.pack()).hex() == '0b1bae4beaf456349c63c3ce67491fc75a1276d7f9eedd7ea84d6a77f9f3f5f7'
    assert Script.read(script.pack()) == script


class OutPoint:
    def __init__(self, tx_hash: bytearray, index: int):
        assert len(tx_hash) == 32
        self.tx_hash = tx_hash
        self.index = index

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.tx_hash == other.tx_hash
        b = self.index == other.index
        return a and b

    @staticmethod
    def read(data: bytearray):
        assert len(data) == 36
        return OutPoint(
            data[0x00:0x20],
            ckb.molecule.U32.read(data[0x20:0x24])
        )

    def pack(self):
        return ckb.molecule.Struct([
            ckb.molecule.Byte32(self.tx_hash),
            ckb.molecule.U32(self.index),
        ]).pack()

    def json(self):
        return {
            'tx_hash': '0x' + self.tx_hash.hex(),
            'index': hex(self.index),
        }


if __name__ == '__main__':
    out_point = OutPoint(
        ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.tx_hash,
        ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.index,
    )
    assert OutPoint.read(out_point.pack()) == out_point


class CellInput:
    def __init__(self, since: int, previous_output: OutPoint):
        self.since = since
        self.previous_output = previous_output

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.since == other.since
        b = self.previous_output == other.previous_output
        return a and b

    @staticmethod
    def read(data: bytearray):
        assert len(data) == 44
        return CellInput(
            ckb.molecule.U64.read(data[0:8]),
            OutPoint.read(data[8:44]),
        )

    def pack(self):
        return ckb.molecule.Struct([
            ckb.molecule.U64(self.since),
            self.previous_output,
        ]).pack()

    def json(self):
        return {
            'since': hex(self.since),
            'previous_output': self.previous_output.json()
        }


if __name__ == '__main__':
    out_point = OutPoint(
        ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.tx_hash,
        ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.index,
    )
    cell_input = CellInput(42, out_point)
    assert CellInput.read(cell_input.pack()) == cell_input


class CellOutput:
    def __init__(self, capacity: int, lock: Script, type: typing.Optional[Script]):
        self.capacity = capacity
        self.lock = lock
        self.type = type

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.capacity == other.capacity
        b = self.lock == other.lock
        c = self.type == other.type
        return a and b and c

    @staticmethod
    def read(data: bytearray):
        result = ckb.molecule.Dynvec.read(data)
        return CellOutput(
            ckb.molecule.U64.read(result[0]),
            Script.read(result[1]),
            Script.read(result[2]) if result[2] else None
        )

    def pack(self):
        return ckb.molecule.Dynvec([
            ckb.molecule.U64(self.capacity),
            self.lock,
            ckb.molecule.Option(self.type),
        ]).pack()

    def json(self):
        return {
            'capacity': hex(self.capacity),
            'lock': self.lock.json(),
            'type': self.type.json() if self.type else None
        }


if __name__ == '__main__':
    lock = Script(
        ckb.config.current.scripts.secp256k1_blake160.code_hash,
        ckb.config.current.scripts.secp256k1_blake160.hash_type,
        bytearray([0x00]) * 20,
    )
    type = Script(
        ckb.config.current.scripts.dao.code_hash,
        ckb.config.current.scripts.dao.hash_type,
        bytearray([0x00]) * 10,
    )
    cell_output = CellOutput(0xffff, lock, type)
    assert CellOutput.read(cell_output.pack()) == cell_output
    cell_output = CellOutput(0xffff, lock, None)
    assert CellOutput.read(cell_output.pack()) == cell_output


class CellDep:
    def __init__(self, out_point: OutPoint, dep_type: int):
        self.out_point = out_point
        self.dep_type = dep_type

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.out_point == other.out_point
        b = self.dep_type == other.dep_type
        return a and b

    @staticmethod
    def read(data: bytearray):
        assert len(data) == 37
        return CellDep(
            OutPoint.read(data[0:36]),
            int(data[36]),
        )

    def pack(self):
        return ckb.molecule.Struct([
            self.out_point,
            ckb.molecule.Byte(self.dep_type),
        ]).pack()

    def json(self):
        return {
            'out_point': self.out_point.json(),
            'dep_type': {
                0: 'code',
                1: 'dep_group',
            }[self.dep_type]
        }


if __name__ == '__main__':
    cell_dep = CellDep(
        OutPoint(
            ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.tx_hash,
            ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.index,
        ),
        ckb.config.current.scripts.secp256k1_blake160.cell_dep.dep_type
    )
    assert CellDep.read(cell_dep.pack()) == cell_dep


class RawTransaction:
    def __init__(
        self,
        version: int,
        cell_deps: typing.List[CellDep],
        header_deps: typing.List[bytearray],
        inputs: typing.List[CellInput],
        outputs: typing.List[CellOutput],
        outputs_data: typing.List[bytearray]
    ):
        self.version = version
        self.cell_deps = cell_deps
        self.header_deps = header_deps
        self.inputs = inputs
        self.outputs = outputs
        self.outputs_data = outputs_data

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.version == other.version
        b = self.cell_deps == other.cell_deps
        c = self.header_deps == other.header_deps
        d = self.inputs == other.inputs
        e = self.outputs == other.outputs
        f = self.outputs_data == other.outputs_data
        return a and b and c and d and e and f

    @staticmethod
    def read(data: bytearray):
        result = ckb.molecule.Dynvec.read(data)
        return RawTransaction(
            ckb.molecule.U32.read(result[0]),
            [CellDep.read(e) for e in ckb.molecule.Fixvec.read(result[1])],
            [ckb.molecule.Byte32.read(e) for e in ckb.molecule.Fixvec.read(result[2])],
            [CellInput.read(e) for e in ckb.molecule.Fixvec.read(result[3])],
            [CellOutput.read(e) for e in ckb.molecule.Dynvec.read(result[4])],
            [ckb.molecule.Bytenn.read(e) for e in ckb.molecule.Dynvec.read(result[5])]
        )

    def pack(self):
        return ckb.molecule.Dynvec([
            ckb.molecule.U32(self.version),
            ckb.molecule.Fixvec(self.cell_deps),
            ckb.molecule.Fixvec([ckb.molecule.Byte32(e) for e in self.header_deps]),
            ckb.molecule.Fixvec(self.inputs),
            ckb.molecule.Dynvec(self.outputs),
            ckb.molecule.Dynvec([ckb.molecule.Bytenn(e) for e in self.outputs_data])
        ]).pack()

    def json(self):
        return {
            'version': hex(self.version),
            'cell_deps': [e.json() for e in self.cell_deps],
            'header_deps': ['0x' + e.hex() for e in self.header_deps],
            'inputs': [e.json() for e in self.inputs],
            'outputs': [e.json() for e in self.outputs],
            'outputs_data': ['0x' + e.hex() for e in self.outputs_data],
        }


if __name__ == '__main__':
    raw_transaction = RawTransaction(0, [], [], [], [], [])
    raw_transaction.cell_deps.append(CellDep(OutPoint(
        ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.tx_hash,
        ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.index,
    ),
        ckb.config.current.scripts.secp256k1_blake160.cell_dep.dep_type
    ))
    raw_transaction.header_deps.append(ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.tx_hash)
    raw_transaction.inputs.append(CellInput(42, OutPoint(
        ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.tx_hash,
        ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.index,
    )))
    raw_transaction.outputs.append(CellOutput(
        0xffff,
        Script(
            ckb.config.current.scripts.secp256k1_blake160.code_hash,
            ckb.config.current.scripts.secp256k1_blake160.hash_type,
            bytearray([0x00]) * 20,
        ),
        None
    ))
    raw_transaction.outputs_data.append(bytearray([0x42]))
    assert hash(raw_transaction.pack()).hex() == '69b6dc37741e1b6e747120135b6efaf5162277f7f3db59211fe791c9ad9121cc'
    assert RawTransaction.read(raw_transaction.pack()) == raw_transaction


class Transaction:
    def __init__(self, raw: RawTransaction, witnesses: typing.List[bytearray]):
        self.raw = raw
        self.witnesses = witnesses

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.raw == other.raw
        b = self.witnesses == other.witnesses
        return a and b

    @staticmethod
    def read(data: bytearray):
        result = ckb.molecule.Dynvec.read(data)
        return Transaction(
            RawTransaction.read(result[0]),
            [ckb.molecule.Bytenn.read(e) for e in ckb.molecule.Dynvec.read(result[1])],
        )

    def pack(self):
        return ckb.molecule.Dynvec([
            self.raw,
            ckb.molecule.Dynvec([ckb.molecule.Bytenn(e) for e in self.witnesses])
        ]).pack()

    def json(self):
        r = self.raw.json()
        r['witnesses'] = [f'0x{e.hex()}' for e in self.witnesses]
        return r


if __name__ == '__main__':
    transaction = Transaction(RawTransaction(0, [], [], [], [], []), [])
    assert Transaction.read(transaction.pack()) == transaction


class WitnessArgs:
    def __init__(
        self,
        lock: typing.Optional[bytearray],
        input_type: typing.Optional[bytearray],
        output_type: typing.Optional[bytearray]
    ):
        self.lock = lock
        self.input_type = input_type
        self.output_type = output_type

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.lock == other.lock
        b = self.input_type == other.input_type
        c = self.output_type == other.output_type
        return a and b and c

    @staticmethod
    def read(data: bytearray):
        result = ckb.molecule.Dynvec.read(data)
        return WitnessArgs(
            ckb.molecule.Bytenn.read(result[0]) if result[0] else None,
            ckb.molecule.Bytenn.read(result[1]) if result[1] else None,
            ckb.molecule.Bytenn.read(result[2]) if result[2] else None,
        )

    def pack(self):
        return ckb.molecule.Dynvec([
            ckb.molecule.Option(ckb.molecule.Bytenn(self.lock) if self.lock else None),
            ckb.molecule.Option(ckb.molecule.Bytenn(self.input_type) if self.input_type else None),
            ckb.molecule.Option(ckb.molecule.Bytenn(self.output_type) if self.output_type else None),
        ]).pack()

    def json(self):
        return {
            'lock': f'0x{self.lock.hex()}' if self.lock else None,
            'input_type': f'0x{self.input_type.hex()}' if self.input_type else None,
            'output_type': f'0x{self.output_type.hex()}' if self.output_type else None,
        }


if __name__ == '__main__':
    witness_args = WitnessArgs(bytearray([0x01]), bytearray([0x02]), bytearray([0x03]))
    assert WitnessArgs.read(witness_args.pack()) == witness_args
