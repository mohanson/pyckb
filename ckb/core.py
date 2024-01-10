import ckb.bech32
import ckb.config
import ckb.molecule
import ckb.secp256k1
import hashlib
import json
import random
import typing

# 1 ckb = 10 ** 8 shannons
shannon = 10 ** 8
# https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md
# The Type ID code cell uses a special type script hash, which is just the ascii codes in hex of the text TYPE_ID.
type_id_code_hash = bytearray.fromhex('00000000000000000000000000000000000000000000000000545950455f4944')
type_id_hash_type = 1


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
    def molecule_read(data: bytearray):
        assert len(data) == 32
        return PriKey(int.from_bytes(data))

    def molecule(self):
        return bytearray(self.n.to_bytes(32))

    @staticmethod
    def json_read(data: str):
        return PriKey(int(data, 16))

    def json(self):
        return f'0x{self.n:064x}'

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
            # Here we do not adjust the sign of s.
            # Doc: https://ethereum.stackexchange.com/questions/55245/why-is-s-in-transaction-signature-limited-to-n-21
            # For BTC, v is in the prefix.
            # For CKB, v is in the suffix.
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
    def molecule_read(data: bytearray):
        assert len(data) == 33
        o = data[0]
        x = int.from_bytes(data[1:33])
        y_x_y = x * x * x + ckb.secp256k1.A.x * x + ckb.secp256k1.B.x
        y = pow(y_x_y, (ckb.secp256k1.P + 1) // 4, ckb.secp256k1.P)
        if y & 1 != o - 2:
            return PubKey(x, -y % ckb.secp256k1.P)
        else:
            return PubKey(x, +y)

    def molecule(self):
        r = bytearray()
        if self.y & 1 == 0:
            r.append(0x02)
        else:
            r.append(0x03)
        r.extend(self.x.to_bytes(32))
        return r

    def json(self):
        return {
            'x': f'0x{self.x:064x}',
            'y': f'0x{self.y:064x}'
        }


class Script:
    def __init__(self, code_hash: bytearray, hash_type: int, args: bytearray):
        assert len(code_hash) == 32
        assert hash_type in [0, 1, 2]  # 0 => data, 1 => type, 2 => data1
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
    def molecule_read(data: bytearray):
        result = ckb.molecule.Dynvec.molecule_read(data)
        code_hash = result[0]
        hash_type = int(result[1][0])
        args = ckb.molecule.Bytenn.molecule_read(result[2])
        return Script(code_hash, hash_type, args)

    def molecule(self):
        return ckb.molecule.Dynvec([
            ckb.molecule.Byte32(self.code_hash),
            ckb.molecule.Byte(self.hash_type),
            ckb.molecule.Bytenn(self.args)
        ]).molecule()

    @staticmethod
    def json_read(data: dict):
        code_hash = bytearray.fromhex(data['code_hash'][2:])
        hash_type = {
            'data': 0,
            'type': 1,
            'data1': 2,
        }[data['hash_type']]
        args = bytearray.fromhex(data['args'][2:])
        return Script(code_hash, hash_type, args)

    def json(self):
        return {
            'code_hash': f'0x{self.code_hash.hex()}',
            'hash_type': {
                0: 'data',
                1: 'type',
                2: 'data1',
            }[self.hash_type],
            'args': f'0x{self.args.hex()}',
        }

    def hash(self):
        return hash(self.molecule())


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
    def molecule_read(data: bytearray):
        assert len(data) == 36
        return OutPoint(
            data[0x00:0x20],
            ckb.molecule.U32.molecule_read(data[0x20:0x24])
        )

    def molecule(self):
        return ckb.molecule.Struct([
            ckb.molecule.Byte32(self.tx_hash),
            ckb.molecule.U32(self.index),
        ]).molecule()

    @staticmethod
    def json_read(data: dict):
        return OutPoint(bytearray.fromhex(data['tx_hash'][2:]), int(data['index'], 16))

    def json(self):
        return {
            'tx_hash': '0x' + self.tx_hash.hex(),
            'index': hex(self.index),
        }


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
    def molecule_read(data: bytearray):
        assert len(data) == 44
        return CellInput(
            ckb.molecule.U64.molecule_read(data[0:8]),
            OutPoint.molecule_read(data[8:44]),
        )

    def molecule(self):
        return ckb.molecule.Struct([
            ckb.molecule.U64(self.since),
            self.previous_output,
        ]).molecule()

    @staticmethod
    def json_read(data: dict):
        since = int(data['since'], 16)
        previous_output = OutPoint.json_read(data['previous_output'])
        return CellInput(since, previous_output)

    def json(self):
        return {
            'since': hex(self.since),
            'previous_output': self.previous_output.json()
        }


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
    def molecule_read(data: bytearray):
        result = ckb.molecule.Dynvec.molecule_read(data)
        return CellOutput(
            ckb.molecule.U64.molecule_read(result[0]),
            Script.molecule_read(result[1]),
            Script.molecule_read(result[2]) if result[2] else None
        )

    def molecule(self):
        return ckb.molecule.Dynvec([
            ckb.molecule.U64(self.capacity),
            self.lock,
            ckb.molecule.Option(self.type),
        ]).molecule()

    @staticmethod
    def json_read(data: dict):
        capacity = int(data['capacity'], 16)
        lock = Script.json_read(data['lock'])
        type = Script.json_read(data['type']) if data['type'] else None
        return CellOutput(capacity, lock, type)

    def json(self):
        return {
            'capacity': hex(self.capacity),
            'lock': self.lock.json(),
            'type': self.type.json() if self.type else None
        }


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
    def molecule_read(data: bytearray):
        assert len(data) == 37
        return CellDep(
            OutPoint.molecule_read(data[0:36]),
            int(data[36]),
        )

    def molecule(self):
        return ckb.molecule.Struct([
            self.out_point,
            ckb.molecule.Byte(self.dep_type),
        ]).molecule()

    @staticmethod
    def json_read(data: dict):
        out_point = OutPoint.json_read(data['out_point'])
        dep_type = {
            'code': 0,
            'dep_group': 1
        }[data['dep_type']]
        return CellDep(out_point, dep_type)

    def json(self):
        return {
            'out_point': self.out_point.json(),
            'dep_type': {
                0: 'code',
                1: 'dep_group',
            }[self.dep_type]
        }

    @staticmethod
    def conf_read(data: dict):
        return CellDep(OutPoint(data.out_point.tx_hash, data.out_point.index), data.dep_type)


class TransactionRaw:
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
    def molecule_read(data: bytearray):
        result = ckb.molecule.Dynvec.molecule_read(data)
        return TransactionRaw(
            ckb.molecule.U32.molecule_read(result[0]),
            [CellDep.molecule_read(e) for e in ckb.molecule.Fixvec.molecule_read(result[1])],
            [ckb.molecule.Byte32.molecule_read(e) for e in ckb.molecule.Fixvec.molecule_read(result[2])],
            [CellInput.molecule_read(e) for e in ckb.molecule.Fixvec.molecule_read(result[3])],
            [CellOutput.molecule_read(e) for e in ckb.molecule.Dynvec.molecule_read(result[4])],
            [ckb.molecule.Bytenn.molecule_read(e) for e in ckb.molecule.Dynvec.molecule_read(result[5])]
        )

    def molecule(self):
        return ckb.molecule.Dynvec([
            ckb.molecule.U32(self.version),
            ckb.molecule.Fixvec(self.cell_deps),
            ckb.molecule.Fixvec([ckb.molecule.Byte32(e) for e in self.header_deps]),
            ckb.molecule.Fixvec(self.inputs),
            ckb.molecule.Dynvec(self.outputs),
            ckb.molecule.Dynvec([ckb.molecule.Bytenn(e) for e in self.outputs_data])
        ]).molecule()

    @staticmethod
    def json_read(data: dict):
        version = int(data['version'], 16)
        cell_deps = [CellDep.json_read(e) for e in data['cell_deps']]
        header_deps = [bytearray.fromhex(e[2:]) for e in data['header_deps']]
        inputs = [CellInput.json_read(e) for e in data['inputs']]
        outputs = [CellOutput.json_read(e) for e in data['outputs']]
        outputs_data = [bytearray.fromhex(e[2:]) for e in data['outputs_data']]
        return TransactionRaw(version, cell_deps, header_deps, inputs, outputs, outputs_data)

    def json(self):
        return {
            'version': hex(self.version),
            'cell_deps': [e.json() for e in self.cell_deps],
            'header_deps': ['0x' + e.hex() for e in self.header_deps],
            'inputs': [e.json() for e in self.inputs],
            'outputs': [e.json() for e in self.outputs],
            'outputs_data': ['0x' + e.hex() for e in self.outputs_data],
        }

    def hash(self):
        return hash(self.molecule())


class Transaction:
    def __init__(self, raw: TransactionRaw, witnesses: typing.List[bytearray]):
        self.raw = raw
        self.witnesses = witnesses

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.raw == other.raw
        b = self.witnesses == other.witnesses
        return a and b

    @staticmethod
    def molecule_read(data: bytearray):
        result = ckb.molecule.Dynvec.molecule_read(data)
        return Transaction(
            TransactionRaw.molecule_read(result[0]),
            [ckb.molecule.Bytenn.molecule_read(e) for e in ckb.molecule.Dynvec.molecule_read(result[1])],
        )

    def molecule(self):
        return ckb.molecule.Dynvec([
            self.raw,
            ckb.molecule.Dynvec([ckb.molecule.Bytenn(e) for e in self.witnesses])
        ]).molecule()

    @staticmethod
    def json_read(data: dict):
        raw = TransactionRaw.json_read(data)
        witnesses = [bytearray.fromhex(e[2:]) for e in data['witnesses']]
        return Transaction(raw, witnesses)

    def json(self):
        r = self.raw.json()
        r['witnesses'] = [f'0x{e.hex()}' for e in self.witnesses]
        return r


def epoch_encode(e: int, i: int, l: int) -> int:
    assert 0 <= e and e <= 0xffffff
    assert 0 <= i and i <= 0xffff
    assert 0 <= l and l <= 0xffff
    return l << 0x28 | i << 0x18 | e


def epoch_decode(v: int):
    e = v & 0xffffff
    i = v >> 0x18 & 0xffff
    l = v >> 0x28 & 0xffff
    return e, i, l


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
    def molecule_read(data: bytearray):
        result = ckb.molecule.Dynvec.molecule_read(data)
        return WitnessArgs(
            ckb.molecule.Bytenn.molecule_read(result[0]) if result[0] else None,
            ckb.molecule.Bytenn.molecule_read(result[1]) if result[1] else None,
            ckb.molecule.Bytenn.molecule_read(result[2]) if result[2] else None,
        )

    def molecule(self):
        return ckb.molecule.Dynvec([
            ckb.molecule.Option(ckb.molecule.Bytenn(self.lock) if self.lock else None),
            ckb.molecule.Option(ckb.molecule.Bytenn(self.input_type) if self.input_type else None),
            ckb.molecule.Option(ckb.molecule.Bytenn(self.output_type) if self.output_type else None),
        ]).molecule()

    def json(self):
        return {
            'lock': f'0x{self.lock.hex()}' if self.lock else None,
            'input_type': f'0x{self.input_type.hex()}' if self.input_type else None,
            'output_type': f'0x{self.output_type.hex()}' if self.output_type else None,
        }
