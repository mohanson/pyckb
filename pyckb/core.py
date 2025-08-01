import hashlib
import json
import pyckb.bech32
import pyckb.config
import pyckb.ecdsa
import pyckb.molecule
import pyckb.secp256k1
import secrets
import typing

# https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md
# The Type ID code cell uses a special type script hash, which is just the ascii codes in hex of the text TYPE_ID.
type_id_code_hash = bytearray.fromhex('00000000000000000000000000000000000000000000000000545950455f4944')
type_id_hash_type = 1

# Specifies how the script code_hash is used to match the script code and how to run the code.
script_hash_type_data = 0
script_hash_type_type = 1
script_hash_type_data1 = 2
script_hash_type_data2 = 4


def hash(data: bytearray) -> bytearray:
    return bytearray(hashlib.blake2b(data, digest_size=32, person=b'ckb-default-hash').digest())


class PriKey:
    def __init__(self, n: int) -> None:
        self.n = n

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def __eq__(self, other: typing.Self) -> bool:
        return self.n == other.n

    def json(self) -> typing.Dict:
        return {
            'n': f'{self.n:064x}',
        }

    def molecule(self) -> bytearray:
        return bytearray(self.n.to_bytes(32))

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        assert len(data) == 32
        return PriKey(int.from_bytes(data))

    def pubkey(self):
        pubkey = pyckb.secp256k1.G * pyckb.secp256k1.Fr(self.n)
        return PubKey(pubkey.x.x, pubkey.y.x)

    @classmethod
    def random(cls) -> typing.Self:
        return PriKey(max(1, secrets.randbelow(pyckb.secp256k1.N)))

    def sign(self, data: bytearray) -> bytearray:
        assert len(data) == 32
        m = pyckb.secp256k1.Fr(int.from_bytes(data))
        r, s, v = pyckb.ecdsa.sign(pyckb.secp256k1.Fr(self.n), m)
        return bytearray(r.x.to_bytes(32)) + bytearray(s.x.to_bytes(32)) + bytearray([v])


class PubKey:
    def __init__(self, x: int, y: int) -> None:
        # The public key must be on the curve.
        _ = pyckb.secp256k1.Pt(pyckb.secp256k1.Fq(x), pyckb.secp256k1.Fq(y))
        self.x = x
        self.y = y

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.x == other.x,
            self.y == other.y,
        ])

    def json(self) -> typing.Dict:
        return {
            'x': f'{self.x:064x}',
            'y': f'{self.y:064x}'
        }

    def pt(self) -> pyckb.secp256k1.Pt:
        return pyckb.secp256k1.Pt(pyckb.secp256k1.Fq(self.x), pyckb.secp256k1.Fq(self.y))

    @classmethod
    def pt_decode(cls, data: pyckb.secp256k1.Pt) -> typing.Self:
        return PubKey(data.x.x, data.y.x)

    def sec(self) -> bytearray:
        # The Standards of Efficient Cryptography (SEC) encoding is used to serialize ECDSA public keys. Public keys in
        # Bitcoin are ECDSA points consisting of two coordinates (x,y). x and y may be smaller than 32 bytes in which
        # case they must be padded with zeros to 32 bytes (H/T Coding Enthusiast).
        r = bytearray()
        if self.y & 1 == 0:
            r.append(0x02)
        else:
            r.append(0x03)
        r.extend(self.x.to_bytes(32))
        return r

    @classmethod
    def sec_decode(cls, data: bytearray) -> typing.Self:
        p = data[0]
        assert p in [0x02, 0x03, 0x04]
        x = int.from_bytes(data[1:33])
        if p == 0x04:
            y = int.from_bytes(data[33:65])
        else:
            y_x_y = x * x * x + pyckb.secp256k1.A.x * x + pyckb.secp256k1.B.x
            y = pow(y_x_y, (pyckb.secp256k1.P + 1) // 4, pyckb.secp256k1.P)
            if y & 1 != p - 2:
                y = -y % pyckb.secp256k1.P
        return PubKey(x, y)


class Script:
    def __init__(self, code_hash: bytearray, hash_type: int, args: bytearray) -> None:
        assert len(code_hash) == 32
        assert hash_type in [
            script_hash_type_data,
            script_hash_type_type,
            script_hash_type_data1,
            script_hash_type_data2,
        ]
        self.code_hash = code_hash
        self.hash_type = hash_type
        self.args = args

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.code_hash == other.code_hash,
            self.hash_type == other.hash_type,
            self.args == other.args,
        ])

    def addr(self) -> str:
        # See: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md
        # See: https://github.com/rev-chaos/ckb-address-demo/blob/master/ckb_addr_test.py
        payload = bytearray()
        payload.append(0x00)
        # Append secp256k1 code hash
        payload.extend(self.code_hash)
        payload.append(self.hash_type)
        payload.extend(self.args)
        return pyckb.bech32.encode(pyckb.config.current.hrp, payload)

    @classmethod
    def addr_decode(cls, data: str) -> typing.Self:
        payload = pyckb.bech32.decode(pyckb.config.current.hrp, data)
        assert payload[0] == 0
        code_hash = payload[1:33]
        hash_type = payload[33]
        args = payload[34:]
        return Script(code_hash, hash_type, args)

    def hash(self) -> bytearray:
        return hash(self.molecule())

    def json(self) -> typing.Dict:
        return {
            'code_hash': self.code_hash.hex(),
            'hash_type': self.hash_type,
            'args': self.args.hex(),
        }

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_dynvec([
            pyckb.molecule.Byte32(self.code_hash).molecule(),
            pyckb.molecule.Byte(self.hash_type).molecule(),
            pyckb.molecule.Bytes(self.args).molecule()
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_dynvec(data)
        return Script(
            pyckb.molecule.Byte32.molecule_decode(result[0]),
            pyckb.molecule.Byte.molecule_decode(result[1]),
            pyckb.molecule.Bytes.molecule_decode(result[2]),
        )

    def rpc(self) -> typing.Dict:
        return {
            'code_hash': f'0x{self.code_hash.hex()}',
            'hash_type': {
                script_hash_type_data: 'data',
                script_hash_type_type: 'type',
                script_hash_type_data1: 'data1',
                script_hash_type_data2: 'data2',
            }[self.hash_type],
            'args': f'0x{self.args.hex()}',
        }

    @classmethod
    def rpc_decode(cls, data: typing.Dict) -> typing.Self:
        return Script(
            bytearray.fromhex(data['code_hash'][2:]),
            {
                'data': script_hash_type_data,
                'type': script_hash_type_type,
                'data1': script_hash_type_data1,
                'data2': script_hash_type_data2,
            }[data['hash_type']],
            bytearray.fromhex(data['args'][2:]),
        )


class OutPoint:
    def __init__(self, tx_hash: bytearray, index: int) -> None:
        assert len(tx_hash) == 32
        self.tx_hash = tx_hash
        self.index = index

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.tx_hash == other.tx_hash,
            self.index == other.index,
        ])

    def __hash__(self) -> int:
        return int.from_bytes(self.molecule())

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'tx_hash': self.tx_hash.hex(),
            'index': self.index,
        }

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_seq([
            pyckb.molecule.Byte32(self.tx_hash).molecule(),
            pyckb.molecule.U32(self.index).molecule(),
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_seq(data, [
            pyckb.molecule.Byte32.molecule_size(),
            pyckb.molecule.U32.molecule_size(),
        ])
        return OutPoint(
            pyckb.molecule.Byte32.molecule_decode(result[0]),
            pyckb.molecule.U32.molecule_decode(result[1])
        )

    @classmethod
    def molecule_size(cls) -> int:
        return pyckb.molecule.Byte32.molecule_size() + pyckb.molecule.U32.molecule_size()

    def rpc(self) -> typing.Dict:
        return {
            'tx_hash': '0x' + self.tx_hash.hex(),
            'index': hex(self.index),
        }

    @classmethod
    def rpc_decode(cls, data: typing.Dict) -> typing.Self:
        return OutPoint(
            bytearray.fromhex(data['tx_hash'][2:]),
            int(data['index'], 16),
        )


class CellInput:
    def __init__(self, since: int, previous_output: OutPoint) -> None:
        self.since = since
        self.previous_output = previous_output

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.since == other.since,
            self.previous_output == other.previous_output,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'since': self.since,
            'previous_output': self.previous_output.json()
        }

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_seq([
            pyckb.molecule.U64(self.since).molecule(),
            self.previous_output.molecule(),
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_seq(data, [
            pyckb.molecule.U64.molecule_size(),
            OutPoint.molecule_size(),
        ])
        return CellInput(
            pyckb.molecule.U64.molecule_decode(result[0]),
            OutPoint.molecule_decode(result[1]),
        )

    @classmethod
    def molecule_size(cls) -> int:
        return pyckb.molecule.U64.molecule_size() + OutPoint.molecule_size()

    def rpc(self) -> typing.Dict:
        return {
            'since': hex(self.since),
            'previous_output': self.previous_output.rpc()
        }

    @classmethod
    def rpc_decode(cls, data: typing.Dict) -> typing.Self:
        return CellInput(
            int(data['since'], 16),
            OutPoint.rpc_decode(data['previous_output']),
        )


class CellOutput:
    def __init__(self, capacity: int, lock: Script, type: Script | None) -> None:
        self.capacity = capacity
        self.lock = lock
        self.type = type

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.capacity == other.capacity,
            self.lock == other.lock,
            self.type == other.type,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'capacity': self.capacity,
            'lock': self.lock.json(),
            'type': self.type.json() if self.type else None
        }

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_dynvec([
            pyckb.molecule.U64(self.capacity).molecule(),
            self.lock.molecule(),
            self.type.molecule() if self.type else bytearray(),
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_dynvec(data)
        return CellOutput(
            pyckb.molecule.U64.molecule_decode(result[0]),
            Script.molecule_decode(result[1]),
            Script.molecule_decode(result[2]) if result[2] else None
        )

    def rpc(self) -> typing.Dict:
        return {
            'capacity': hex(self.capacity),
            'lock': self.lock.rpc(),
            'type': self.type.rpc() if self.type else None
        }

    @classmethod
    def rpc_decode(cls, data: typing.Dict) -> typing.Self:
        return CellOutput(
            int(data['capacity'], 16),
            Script.rpc_decode(data['lock']),
            Script.rpc_decode(data['type']) if data['type'] else None,
        )


class CellDep:
    def __init__(self, out_point: OutPoint, dep_type: int) -> None:
        self.out_point = out_point
        self.dep_type = dep_type

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.out_point == other.out_point,
            self.dep_type == other.dep_type,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    @classmethod
    def conf_decode(cls, data: typing.Dict) -> typing.Self:
        return CellDep(OutPoint(data.out_point.tx_hash, data.out_point.index), data.dep_type)

    def json(self) -> typing.Dict:
        return {
            'out_point': self.out_point.json(),
            'dep_type': self.dep_type,
        }

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_seq([
            self.out_point.molecule(),
            pyckb.molecule.Byte(self.dep_type).molecule(),
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_seq(data, [
            OutPoint.molecule_size(),
            pyckb.molecule.Byte.molecule_size(),
        ])
        return CellDep(
            OutPoint.molecule_decode(result[0]),
            pyckb.molecule.Byte.molecule_decode(result[1]),
        )

    @classmethod
    def molecule_size(cls) -> int:
        return OutPoint.molecule_size() + pyckb.molecule.Byte.molecule_size()

    def rpc(self) -> typing.Dict:
        return {
            'out_point': self.out_point.rpc(),
            'dep_type': {0: 'code', 1: 'dep_group'}[self.dep_type]
        }

    @classmethod
    def rpc_decode(cls, data: typing.Dict) -> typing.Self:
        return CellDep(
            OutPoint.rpc_decode(data['out_point']),
            {'code': 0, 'dep_group': 1}[data['dep_type']],
        )


class RawTransaction:
    def __init__(
        self,
        version: int,
        cell_deps: list[CellDep],
        header_deps: list[bytearray],
        inputs: list[CellInput],
        outputs: list[CellOutput],
        outputs_data: list[bytearray]
    ) -> None:
        self.version = version
        self.cell_deps = cell_deps
        self.header_deps = header_deps
        self.inputs = inputs
        self.outputs = outputs
        self.outputs_data = outputs_data

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.version == other.version,
            self.cell_deps == other.cell_deps,
            self.header_deps == other.header_deps,
            self.inputs == other.inputs,
            self.outputs == other.outputs,
            self.outputs_data == other.outputs_data,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def hash(self) -> bytearray:
        return hash(self.molecule())

    def json(self) -> typing.Dict:
        return {
            'version': self.version,
            'cell_deps': [e.json() for e in self.cell_deps],
            'header_deps': [e.hex() for e in self.header_deps],
            'inputs': [e.json() for e in self.inputs],
            'outputs': [e.json() for e in self.outputs],
            'outputs_data': [e.hex() for e in self.outputs_data],
        }

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_dynvec([
            pyckb.molecule.U32(self.version).molecule(),
            pyckb.molecule.encode_fixvec([e.molecule() for e in self.cell_deps]),
            pyckb.molecule.encode_fixvec([pyckb.molecule.Byte32(e).molecule() for e in self.header_deps]),
            pyckb.molecule.encode_fixvec([e.molecule() for e in self.inputs]),
            pyckb.molecule.encode_dynvec([e.molecule() for e in self.outputs]),
            pyckb.molecule.encode_dynvec([pyckb.molecule.Bytes(e).molecule() for e in self.outputs_data])
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_dynvec(data)
        return RawTransaction(
            pyckb.molecule.U32.molecule_decode(result[0]),
            [CellDep.molecule_decode(e) for e in pyckb.molecule.decode_fixvec(result[1])],
            [pyckb.molecule.Byte32.molecule_decode(e) for e in pyckb.molecule.decode_fixvec(result[2])],
            [CellInput.molecule_decode(e) for e in pyckb.molecule.decode_fixvec(result[3])],
            [CellOutput.molecule_decode(e) for e in pyckb.molecule.decode_dynvec(result[4])],
            [pyckb.molecule.Bytes.molecule_decode(e) for e in pyckb.molecule.decode_dynvec(result[5])]
        )

    def rpc(self) -> typing.Dict:
        return {
            'version': hex(self.version),
            'cell_deps': [e.rpc() for e in self.cell_deps],
            'header_deps': ['0x' + e.hex() for e in self.header_deps],
            'inputs': [e.rpc() for e in self.inputs],
            'outputs': [e.rpc() for e in self.outputs],
            'outputs_data': ['0x' + e.hex() for e in self.outputs_data],
        }

    @classmethod
    def rpc_decode(cls, data: typing.Dict) -> typing.Self:
        return RawTransaction(
            int(data['version'], 16),
            [CellDep.rpc_decode(e) for e in data['cell_deps']],
            [bytearray.fromhex(e[2:]) for e in data['header_deps']],
            [CellInput.rpc_decode(e) for e in data['inputs']],
            [CellOutput.rpc_decode(e) for e in data['outputs']],
            [bytearray.fromhex(e[2:]) for e in data['outputs_data']],
        )


class Transaction:
    def __init__(self, raw: RawTransaction, witnesses: list[bytearray]) -> None:
        self.raw = raw
        self.witnesses = witnesses

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.raw == other.raw,
            self.witnesses == other.witnesses,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def hash_sighash_all(self, major: int, other: typing.List[int]) -> bytearray:
        for e in WitnessArgs.molecule_decode(self.witnesses[major]).lock:
            assert (e == 0)
        major_w = self.witnesses[major]
        major_l = len(major_w)
        b = bytearray()
        b.extend(self.raw.hash())
        b.extend(major_l.to_bytes(8, 'little'))
        b.extend(major_w)
        for e in [e for e in other if e < self.witnesses.len()]:
            w = self.witnesses[e]
            l = len(w)
            b.extend(l.to_bytes(8, 'little'))
            b.extend(w)
        for e in self.witnesses[len(self.raw.inputs):]:
            l = len(e)
            b.extend(l.to_bytes(8, 'little'))
            b.extend(e)
        return hash(b)

    def json(self) -> typing.Dict:
        r = self.raw.json()
        r['witnesses'] = [e.hex() for e in self.witnesses]
        return r

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_dynvec([
            self.raw.molecule(),
            pyckb.molecule.encode_dynvec([pyckb.molecule.Bytes(e).molecule() for e in self.witnesses])
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_dynvec(data)
        return Transaction(
            RawTransaction.molecule_decode(result[0]),
            [pyckb.molecule.Bytes.molecule_decode(e) for e in pyckb.molecule.decode_dynvec(result[1])],
        )

    def rpc(self) -> typing.Dict:
        r = self.raw.rpc()
        r['witnesses'] = [f'0x{e.hex()}' for e in self.witnesses]
        return r

    @classmethod
    def rpc_decode(cls, data: typing.Dict) -> typing.Self:
        return Transaction(
            RawTransaction.rpc_decode(data),
            [bytearray.fromhex(e[2:]) for e in data['witnesses']],
        )


def epoch_encode(e: int, i: int, l: int) -> int:
    assert 0 <= e and e <= 0xffffff
    assert 0 <= i and i <= 0xffff
    assert 0 <= l and l <= 0xffff
    return l << 0x28 | i << 0x18 | e


def epoch_decode(v: int) -> typing.Tuple[int, int, int]:
    e = v & 0xffffff
    i = v >> 0x18 & 0xffff
    l = v >> 0x28 & 0xffff
    return e, i, l


class WitnessArgs:
    def __init__(self, lock: bytearray | None, input_type: bytearray | None, output_type: bytearray | None) -> None:
        self.lock = lock
        self.input_type = input_type
        self.output_type = output_type

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.lock == other.lock,
            self.input_type == other.input_type,
            self.output_type == other.output_type,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'lock': self.lock.hex() if self.lock else None,
            'input_type': self.input_type.hex() if self.input_type else None,
            'output_type': self.output_type.hex() if self.output_type else None,
        }

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_dynvec([
            pyckb.molecule.Bytes(self.lock).molecule() if self.lock else bytearray(),
            pyckb.molecule.Bytes(self.input_type).molecule() if self.input_type else bytearray(),
            pyckb.molecule.Bytes(self.output_type).molecule() if self.output_type else bytearray(),
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_dynvec(data)
        return WitnessArgs(
            pyckb.molecule.Bytes.molecule_decode(result[0]) if result[0] else None,
            pyckb.molecule.Bytes.molecule_decode(result[1]) if result[1] else None,
            pyckb.molecule.Bytes.molecule_decode(result[2]) if result[2] else None,
        )


class RawHeader:
    def __init__(
        self,
        version: int,
        compact_target: int,
        timestamp: int,
        number: int,
        epoch: int,
        parent_hash: bytearray,
        transactions_root: bytearray,
        proposals_hash: bytearray,
        extra_hash: bytearray,
        dao: bytearray,
    ) -> None:
        self.version = version
        self.compact_target = compact_target
        self.timestamp = timestamp
        self.number = number
        self.epoch = epoch
        self.parent_hash = parent_hash
        self.transactions_root = transactions_root
        self.proposals_hash = proposals_hash
        self.extra_hash = extra_hash
        self.dao = dao

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.version == other.version,
            self.compact_target == other.compact_target,
            self.timestamp == other.timestamp,
            self.number == other.number,
            self.epoch == other.epoch,
            self.parent_hash == other.parent_hash,
            self.transactions_root == other.transactions_root,
            self.proposals_hash == other.proposals_hash,
            self.extra_hash == other.extra_hash,
            self.dao == other.dao,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'version': self.version,
            'compact_target': self.compact_target,
            'timestamp': self.timestamp,
            'number': self.number,
            'epoch': self.epoch,
            'parent_hash': self.parent_hash.hex(),
            'transactions_root': self.transactions_root.hex(),
            'proposals_hash': self.proposals_hash.hex(),
            'extra_hash': self.extra_hash.hex(),
            'dao': self.dao.hex(),
        }

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_seq([
            pyckb.molecule.U32(self.version).molecule(),
            pyckb.molecule.U32(self.compact_target).molecule(),
            pyckb.molecule.U64(self.timestamp).molecule(),
            pyckb.molecule.U64(self.number).molecule(),
            pyckb.molecule.U64(self.epoch).molecule(),
            pyckb.molecule.Byte32(self.parent_hash).molecule(),
            pyckb.molecule.Byte32(self.transactions_root).molecule(),
            pyckb.molecule.Byte32(self.proposals_hash).molecule(),
            pyckb.molecule.Byte32(self.extra_hash).molecule(),
            pyckb.molecule.Byte32(self.dao).molecule(),
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_seq(data, [
            pyckb.molecule.U32.molecule_size(),
            pyckb.molecule.U32.molecule_size(),
            pyckb.molecule.U64.molecule_size(),
            pyckb.molecule.U64.molecule_size(),
            pyckb.molecule.U64.molecule_size(),
            pyckb.molecule.Byte32.molecule_size(),
            pyckb.molecule.Byte32.molecule_size(),
            pyckb.molecule.Byte32.molecule_size(),
            pyckb.molecule.Byte32.molecule_size(),
            pyckb.molecule.Byte32.molecule_size(),
        ])
        return RawHeader(
            pyckb.molecule.U32.molecule_decode(result[0]),
            pyckb.molecule.U32.molecule_decode(result[1]),
            pyckb.molecule.U64.molecule_decode(result[2]),
            pyckb.molecule.U64.molecule_decode(result[3]),
            pyckb.molecule.U64.molecule_decode(result[4]),
            pyckb.molecule.Byte32.molecule_decode(result[5]),
            pyckb.molecule.Byte32.molecule_decode(result[6]),
            pyckb.molecule.Byte32.molecule_decode(result[7]),
            pyckb.molecule.Byte32.molecule_decode(result[8]),
            pyckb.molecule.Byte32.molecule_decode(result[9]),
        )

    @classmethod
    def molecule_size(cls) -> int:
        return sum([
            pyckb.molecule.U32.molecule_size(),
            pyckb.molecule.U32.molecule_size(),
            pyckb.molecule.U64.molecule_size(),
            pyckb.molecule.U64.molecule_size(),
            pyckb.molecule.U64.molecule_size(),
            pyckb.molecule.Byte32.molecule_size(),
            pyckb.molecule.Byte32.molecule_size(),
            pyckb.molecule.Byte32.molecule_size(),
            pyckb.molecule.Byte32.molecule_size(),
            pyckb.molecule.Byte32.molecule_size(),
        ])

    def rpc(self) -> typing.Dict:
        return {
            'version': f'0x{hex(self.version)}',
            'compact_target': f'0x{hex(self.compact_target)}',
            'timestamp': f'0x{hex(self.timestamp)}',
            'number': f'0x{hex(self.number)}',
            'epoch': f'0x{hex(self.epoch)}',
            'parent_hash': f'0x{self.parent_hash.hex()}',
            'transactions_root': f'0x{self.transactions_root.hex()}',
            'proposals_hash': f'0x{self.proposals_hash.hex()}',
            'extra_hash': f'0x{self.extra_hash.hex()}',
            'dao': f'0x{self.dao.hex()}',
        }

    @classmethod
    def rpc_decode(cls, data: typing.Dict) -> typing.Self:
        return RawHeader(
            version=int(data['version'], 16),
            compact_target=int(data['compact_target'], 16),
            timestamp=int(data['timestamp'], 16),
            number=int(data['number'], 16),
            epoch=int(data['epoch'], 16),
            parent_hash=bytearray.fromhex(data['parent_hash'][2:]),
            transactions_root=bytearray.fromhex(data['transactions_root'][2:]),
            proposals_hash=bytearray.fromhex(data['proposals_hash'][2:]),
            extra_hash=bytearray.fromhex(data['extra_hash'][2:]),
            dao=bytearray.fromhex(data['dao'][2:]),
        )


class Header:
    def __init__(self, raw: RawHeader, nonce: int) -> None:
        self.raw = raw
        self.nonce = nonce

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.raw == other.raw,
            self.nonce == other.nonce,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def hash(self) -> bytearray:
        return hash(self.molecule())

    def json(self) -> typing.Dict:
        r = self.raw.json()
        r['nonce'] = self.nonce
        return r

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_seq([
            self.raw.molecule(),
            pyckb.molecule.U128(self.nonce).molecule(),
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_seq(data, [
            RawHeader.molecule_size(),
            pyckb.molecule.U128.molecule_size(),
        ])
        return Header(
            RawHeader.molecule_decode(result[0]),
            pyckb.molecule.U128.molecule_decode(result[1]),
        )

    @classmethod
    def molecule_size(cls) -> int:
        return RawHeader.molecule_size() + pyckb.molecule.U128.molecule_size()

    def rpc(self) -> typing.Dict:
        r = self.raw.rpc()
        r['nonce'] = f'0x{hex(self.nonce)}'
        return r

    @classmethod
    def rpc_decode(cls, data: typing.Dict) -> typing.Self:
        return Header(
            RawHeader.rpc_decode(data),
            int(data['nonce'], 16),
        )


def dao_encode(c: int, ar: int, s: int, u: int) -> bytearray:
    # CKB's block header has a particular field named dao containing auxiliary information for Nervos DAO's use.
    # https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0023-dao-deposit-withdraw/0023-dao-deposit-withdraw.md
    r = bytearray()
    r.extend(bytearray(c.to_bytes(8, 'little')))
    r.extend(bytearray(ar.to_bytes(8, 'little')))
    r.extend(bytearray(s.to_bytes(8, 'little')))
    r.extend(bytearray(u.to_bytes(8, 'little')))
    return r


def dao_decode(d: bytearray) -> typing.Tuple[int, int, int, int]:
    c = int.from_bytes(d[0x00:0x08], 'little')
    ar = int.from_bytes(d[0x08:0x10], 'little')
    s = int.from_bytes(d[0x10:0x18], 'little')
    u = int.from_bytes(d[0x18:0x20], 'little')
    return c, ar, s, u


class UncleBlock:
    def __init__(self, header: Header, proposals: typing.List[bytearray]) -> None:
        self.header = header
        self.proposals = proposals

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.header == other.header,
            self.proposals == other.proposals,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'header': self.header.json(),
            'proposals': [e.hex() for e in self.proposals],
        }

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_dynvec([
            self.header.molecule(),
            pyckb.molecule.encode_fixvec(self.proposals),
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_dynvec(data)
        return UncleBlock(
            Header.molecule_decode(result[0]),
            pyckb.molecule.decode_fixvec(result[1]),
        )

    def rpc(self) -> typing.Dict:
        return {
            'header': self.header.rpc(),
            'proposals': [f'0x{e.hex()}' for e in self.proposals],
        }

    @classmethod
    def rpc_decode(cls, data: typing.Dict) -> typing.Self:
        return UncleBlock(
            Header.rpc_decode(data['header']),
            [bytearray.fromhex(e[2:]) for e in data['proposals']]
        )


class Block:
    def __init__(
        self,
        header: Header,
        uncles: typing.List[UncleBlock],
        transactions: typing.List[Transaction],
        proposals: typing.List[bytearray],
    ) -> None:
        self.header = header
        self.uncles = uncles
        self.transactions = transactions
        self.proposals = proposals

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.header == other.header,
            self.uncles == other.uncles,
            self.transactions == other.transactions,
            self.proposals == other.proposals,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'header': self.header.json(),
            'uncles': [e.json() for e in self.uncles],
            'transactions': [e.json() for e in self.transactions],
            'proposals': [e.hex() for e in self.proposals],
        }

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_dynvec([
            self.header.molecule(),
            pyckb.molecule.encode_dynvec([e.molecule() for e in self.uncles]),
            pyckb.molecule.encode_dynvec([e.molecule() for e in self.transactions]),
            pyckb.molecule.encode_fixvec(self.proposals),
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_dynvec(data)
        return Block(
            Header.molecule_decode(result[0]),
            [UncleBlock.molecule_decode(e) for e in pyckb.molecule.decode_dynvec(result[1])],
            [Transaction.molecule_decode(e) for e in pyckb.molecule.decode_dynvec(result[2])],
            pyckb.molecule.decode_fixvec(result[3]),
        )

    def rpc(self) -> typing.Dict:
        return {
            'header': self.header.rpc(),
            'uncles': [e.rpc() for e in self.uncles],
            'transactions': [e.rpc() for e in self.transactions],
            'proposals': [f'0x{e.hex()}' for e in self.proposals],
        }

    @classmethod
    def rpc_decode(cls, data: typing.Dict) -> typing.Self:
        return Block(
            Header.rpc_decode(data['header']),
            [UncleBlock.rpc_decode(e) for e in data['uncles']],
            [Transaction.rpc_decode(e) for e in data['transactions']],
            [bytearray.fromhex(e[2:]) for e in data['proposals']],
        )


class BlockV1:
    def __init__(
        self,
        header: Header,
        uncles: typing.List[UncleBlock],
        transactions: typing.List[Transaction],
        proposals: typing.List[bytearray],
        extension: bytearray,
    ) -> None:
        self.header = header
        self.uncles = uncles
        self.transactions = transactions
        self.proposals = proposals
        self.extension = extension

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.header == other.header,
            self.uncles == other.uncles,
            self.transactions == other.transactions,
            self.proposals == other.proposals,
            self.extension == other.extension,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'header': self.header.json(),
            'uncles': [e.json() for e in self.uncles],
            'transactions': [e.json() for e in self.transactions],
            'proposals': [e.hex() for e in self.proposals],
            'extension': self.extension.hex(),
        }

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_dynvec([
            self.header.molecule(),
            pyckb.molecule.encode_dynvec([e.molecule() for e in self.uncles]),
            pyckb.molecule.encode_dynvec([e.molecule() for e in self.transactions]),
            pyckb.molecule.encode_fixvec(self.proposals),
            pyckb.molecule.Bytes(self.extension).molecule(),
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_dynvec(data)
        return BlockV1(
            Header.molecule_decode(result[0]),
            [UncleBlock.molecule_decode(e) for e in pyckb.molecule.decode_dynvec(result[1])],
            [Transaction.molecule_decode(e) for e in pyckb.molecule.decode_dynvec(result[2])],
            pyckb.molecule.decode_fixvec(result[3]),
            pyckb.molecule.Bytes.molecule_decode(result[4]),
        )

    def rpc(self) -> typing.Dict:
        return {
            'header': self.header.rpc(),
            'uncles': [e.rpc() for e in self.uncles],
            'transactions': [e.rpc() for e in self.transactions],
            'proposals': [f'0x{e.hex()}' for e in self.proposals],
            'extension': f'0x{self.extension.hex()}'
        }

    @classmethod
    def rpc_decode(cls, data: typing.Dict) -> typing.Self:
        return BlockV1(
            Header.rpc_decode(data['header']),
            [UncleBlock.rpc_decode(e) for e in data['uncles']],
            [Transaction.rpc_decode(e) for e in data['transactions']],
            [bytearray.fromhex(e[2:]) for e in data['proposals']],
            bytearray.fromhex(data['extension'][2:]),
        )


class CellbaseWitness:
    def __init__(self, lock: Script, message: bytearray) -> None:
        self.lock = lock
        self.message = message

    def __eq__(self, other: typing.Self) -> bool:
        return all([
            self.lock == other.lock,
            self.message == other.message,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'lock': self.lock.json(),
            'message': self.message.hex(),
        }

    def molecule(self) -> bytearray:
        return pyckb.molecule.encode_dynvec([
            self.lock.molecule(),
            pyckb.molecule.Bytes(self.message).molecule(),
        ])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> typing.Self:
        result = pyckb.molecule.decode_dynvec(data)
        return CellbaseWitness(
            Script.molecule_decode(result[0]),
            pyckb.molecule.Bytes.molecule_decode(result[1]),
        )

    def rpc(self) -> typing.Dict:
        return {
            'lock': self.lock.rpc(),
            'message': f'0x{self.message.hex()}',
        }

    @classmethod
    def rpc_deocde(cls, data: typing.Dict) -> typing.Self:
        return CellbaseWitness(
            Script.rpc_decode(data['lock']),
            bytearray.fromhex(data['message'][2:]),
        )
