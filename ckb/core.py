import ckb.bech32
import ckb.config
import ckb.ecdsa
import ckb.molecule
import ckb.secp256k1
import hashlib
import json

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
        return self.n == other.n

    def json(self):
        return f'0x{self.n:064x}'

    @staticmethod
    def json_decode(data: str):
        return PriKey(int(data, 16))

    def molecule(self):
        return bytearray(self.n.to_bytes(32))

    @staticmethod
    def molecule_decode(data: bytearray):
        assert len(data) == 32
        return PriKey(int.from_bytes(data))

    def pubkey(self):
        pubkey = ckb.secp256k1.G * ckb.secp256k1.Fr(self.n)
        return PubKey(pubkey.x.x, pubkey.y.x)

    def sign(self, data: bytearray):
        assert len(data) == 32
        m = ckb.secp256k1.Fr(int.from_bytes(data))
        r, s, v = ckb.ecdsa.sign(ckb.secp256k1.Fr(self.n), m)
        return bytearray(r.x.to_bytes(32)) + bytearray(s.x.to_bytes(32)) + bytearray([v])


class PubKey:
    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        return all([
            self.x == other.x,
            self.y == other.y,
        ])

    def json(self):
        return {
            'x': f'0x{self.x:064x}',
            'y': f'0x{self.y:064x}'
        }

    def sec(self):
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

    @staticmethod
    def sec_decode(data: bytearray):
        p = data[0]
        assert p in [0x02, 0x03, 0x04]
        x = int.from_bytes(data[1:33])
        if p == 0x04:
            y = int.from_bytes(data[33:65])
        else:
            y_x_y = x * x * x + ckb.secp256k1.A.x * x + ckb.secp256k1.B.x
            y = pow(y_x_y, (ckb.secp256k1.P + 1) // 4, ckb.secp256k1.P)
            if y & 1 != p - 2:
                y = -y % ckb.secp256k1.P
        return PubKey(x, y)


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
        return all([
            self.code_hash == other.code_hash,
            self.hash_type == other.hash_type,
            self.args == other.args,
        ])

    def hash(self):
        return hash(self.molecule())

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

    @staticmethod
    def json_decode(data: dict):
        code_hash = bytearray.fromhex(data['code_hash'][2:])
        hash_type = {
            'data': 0,
            'type': 1,
            'data1': 2,
        }[data['hash_type']]
        args = bytearray.fromhex(data['args'][2:])
        return Script(code_hash, hash_type, args)

    def molecule(self):
        return ckb.molecule.encode_dynvec([
            ckb.molecule.Byte32(self.code_hash).molecule(),
            ckb.molecule.Byte(self.hash_type).molecule(),
            ckb.molecule.Bytes(self.args).molecule()
        ])

    @staticmethod
    def molecule_decode(data: bytearray):
        result = ckb.molecule.decode_dynvec(data)
        return Script(
            ckb.molecule.Byte32.molecule_decode(result[0]),
            ckb.molecule.Byte.molecule_decode(result[1]),
            ckb.molecule.Bytes.molecule_decode(result[2]),
        )


def address_encode(script: Script) -> str:
    # See: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md
    # See: https://github.com/rev-chaos/ckb-address-demo/blob/master/ckb_addr_test.py
    payload = bytearray()
    payload.append(0x00)
    # Append secp256k1 code hash
    payload.extend(script.code_hash)
    payload.append(script.hash_type)
    payload.extend(script.args)
    return ckb.bech32.encode(ckb.config.current.hrp, payload)


def address_decode(addr: str) -> Script:
    payload = ckb.bech32.decode(ckb.config.current.hrp, addr)
    assert payload[0] == 0
    code_hash = payload[1:33]
    hash_type = payload[33]
    args = payload[34:]
    return Script(code_hash, hash_type, args)


class OutPoint:
    def __init__(self, tx_hash: bytearray, index: int):
        assert len(tx_hash) == 32
        self.tx_hash = tx_hash
        self.index = index

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        return all([
            self.tx_hash == other.tx_hash,
            self.index == other.index,
        ])

    def json(self):
        return {
            'tx_hash': '0x' + self.tx_hash.hex(),
            'index': hex(self.index),
        }

    @staticmethod
    def json_decode(data: dict):
        return OutPoint(bytearray.fromhex(data['tx_hash'][2:]), int(data['index'], 16))

    def molecule(self):
        return ckb.molecule.encode_seq([
            ckb.molecule.Byte32(self.tx_hash).molecule(),
            ckb.molecule.U32(self.index).molecule(),
        ])

    @staticmethod
    def molecule_decode(data: bytearray):
        result = ckb.molecule.decode_seq(data, [
            ckb.molecule.Byte32.molecule_size(),
            ckb.molecule.U32.molecule_size(),
        ])
        return OutPoint(
            ckb.molecule.Byte32.molecule_decode(result[0]),
            ckb.molecule.U32.molecule_decode(result[1])
        )

    @staticmethod
    def molecule_size():
        return ckb.molecule.Byte32.molecule_size() + ckb.molecule.U32.molecule_size()


class CellInput:
    def __init__(self, since: int, previous_output: OutPoint):
        self.since = since
        self.previous_output = previous_output

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        return all([
            self.since == other.since,
            self.previous_output == other.previous_output,
        ])

    def json(self):
        return {
            'since': hex(self.since),
            'previous_output': self.previous_output.json()
        }

    @staticmethod
    def json_decode(data: dict):
        since = int(data['since'], 16)
        previous_output = OutPoint.json_decode(data['previous_output'])
        return CellInput(since, previous_output)

    def molecule(self):
        return ckb.molecule.encode_seq([
            ckb.molecule.U64(self.since).molecule(),
            self.previous_output.molecule(),
        ])

    @staticmethod
    def molecule_decode(data: bytearray):
        result = ckb.molecule.decode_seq(data, [
            ckb.molecule.U64.molecule_size(),
            OutPoint.molecule_size(),
        ])
        return CellInput(
            ckb.molecule.U64.molecule_decode(result[0]),
            OutPoint.molecule_decode(result[1]),
        )

    @staticmethod
    def molecule_size():
        return ckb.molecule.U64.molecule_size() + OutPoint.molecule_size()


class CellOutput:
    def __init__(self, capacity: int, lock: Script, type: Script | None):
        self.capacity = capacity
        self.lock = lock
        self.type = type

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        return all([
            self.capacity == other.capacity,
            self.lock == other.lock,
            self.type == other.type,
        ])

    def json(self):
        return {
            'capacity': hex(self.capacity),
            'lock': self.lock.json(),
            'type': self.type.json() if self.type else None
        }

    @staticmethod
    def json_decode(data: dict):
        capacity = int(data['capacity'], 16)
        lock = Script.json_decode(data['lock'])
        type = Script.json_decode(data['type']) if data['type'] else None
        return CellOutput(capacity, lock, type)

    def molecule(self):
        return ckb.molecule.encode_dynvec([
            ckb.molecule.U64(self.capacity).molecule(),
            self.lock.molecule(),
            self.type.molecule() if self.type else bytearray(),
        ])

    @staticmethod
    def molecule_decode(data: bytearray):
        result = ckb.molecule.decode_dynvec(data)
        return CellOutput(
            ckb.molecule.U64.molecule_decode(result[0]),
            Script.molecule_decode(result[1]),
            Script.molecule_decode(result[2]) if result[2] else None
        )


class CellDep:
    def __init__(self, out_point: OutPoint, dep_type: int):
        self.out_point = out_point
        self.dep_type = dep_type

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        return all([
            self.out_point == other.out_point,
            self.dep_type == other.dep_type,
        ])

    @staticmethod
    def conf_decode(data: dict):
        return CellDep(OutPoint(data.out_point.tx_hash, data.out_point.index), data.dep_type)

    def json(self):
        return {
            'out_point': self.out_point.json(),
            'dep_type': {
                0: 'code',
                1: 'dep_group',
            }[self.dep_type]
        }

    @staticmethod
    def json_decode(data: dict):
        out_point = OutPoint.json_decode(data['out_point'])
        dep_type = {
            'code': 0,
            'dep_group': 1
        }[data['dep_type']]
        return CellDep(out_point, dep_type)

    def molecule(self):
        return ckb.molecule.encode_seq([
            self.out_point.molecule(),
            ckb.molecule.Byte(self.dep_type).molecule(),
        ])

    @staticmethod
    def molecule_decode(data: bytearray):
        result = ckb.molecule.decode_seq(data, [
            OutPoint.molecule_size(),
            ckb.molecule.Byte.molecule_size(),
        ])
        return CellDep(
            OutPoint.molecule_decode(result[0]),
            ckb.molecule.Byte.molecule_decode(result[1]),
        )

    @staticmethod
    def molecule_size():
        return OutPoint.molecule_size() + ckb.molecule.Byte.molecule_size()


class TransactionRaw:
    def __init__(
        self,
        version: int,
        cell_deps: list[CellDep],
        header_deps: list[bytearray],
        inputs: list[CellInput],
        outputs: list[CellOutput],
        outputs_data: list[bytearray]
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
        return all([
            self.version == other.version,
            self.cell_deps == other.cell_deps,
            self.header_deps == other.header_deps,
            self.inputs == other.inputs,
            self.outputs == other.outputs,
            self.outputs_data == other.outputs_data,
        ])

    def hash(self):
        return hash(self.molecule())

    def json(self):
        return {
            'version': hex(self.version),
            'cell_deps': [e.json() for e in self.cell_deps],
            'header_deps': ['0x' + e.hex() for e in self.header_deps],
            'inputs': [e.json() for e in self.inputs],
            'outputs': [e.json() for e in self.outputs],
            'outputs_data': ['0x' + e.hex() for e in self.outputs_data],
        }

    @staticmethod
    def json_decode(data: dict):
        version = int(data['version'], 16)
        cell_deps = [CellDep.json_decode(e) for e in data['cell_deps']]
        header_deps = [bytearray.fromhex(e[2:]) for e in data['header_deps']]
        inputs = [CellInput.json_decode(e) for e in data['inputs']]
        outputs = [CellOutput.json_decode(e) for e in data['outputs']]
        outputs_data = [bytearray.fromhex(e[2:]) for e in data['outputs_data']]
        return TransactionRaw(version, cell_deps, header_deps, inputs, outputs, outputs_data)

    def molecule(self):
        return ckb.molecule.encode_dynvec([
            ckb.molecule.U32(self.version).molecule(),
            ckb.molecule.encode_fixvec([e.molecule() for e in self.cell_deps]),
            ckb.molecule.encode_fixvec([ckb.molecule.Byte32(e).molecule() for e in self.header_deps]),
            ckb.molecule.encode_fixvec([e.molecule() for e in self.inputs]),
            ckb.molecule.encode_dynvec([e.molecule() for e in self.outputs]),
            ckb.molecule.encode_dynvec([ckb.molecule.Bytes(e).molecule() for e in self.outputs_data])
        ])

    @staticmethod
    def molecule_decode(data: bytearray):
        result = ckb.molecule.decode_dynvec(data)
        return TransactionRaw(
            ckb.molecule.U32.molecule_decode(result[0]),
            [CellDep.molecule_decode(e) for e in ckb.molecule.decode_fixvec(result[1])],
            [ckb.molecule.Byte32.molecule_decode(e) for e in ckb.molecule.decode_fixvec(result[2])],
            [CellInput.molecule_decode(e) for e in ckb.molecule.decode_fixvec(result[3])],
            [CellOutput.molecule_decode(e) for e in ckb.molecule.decode_dynvec(result[4])],
            [ckb.molecule.Bytes.molecule_decode(e) for e in ckb.molecule.decode_dynvec(result[5])]
        )


class Transaction:
    def __init__(self, raw: TransactionRaw, witnesses: list[bytearray]):
        self.raw = raw
        self.witnesses = witnesses

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        return all([
            self.raw == other.raw,
            self.witnesses == other.witnesses,
        ])

    def json(self):
        r = self.raw.json()
        r['witnesses'] = [f'0x{e.hex()}' for e in self.witnesses]
        return r

    @staticmethod
    def json_decode(data: dict):
        raw = TransactionRaw.json_decode(data)
        witnesses = [bytearray.fromhex(e[2:]) for e in data['witnesses']]
        return Transaction(raw, witnesses)

    def molecule(self):
        return ckb.molecule.encode_dynvec([
            self.raw.molecule(),
            ckb.molecule.encode_dynvec([ckb.molecule.Bytes(e).molecule() for e in self.witnesses])
        ])

    @staticmethod
    def molecule_decode(data: bytearray):
        result = ckb.molecule.decode_dynvec(data)
        return Transaction(
            TransactionRaw.molecule_decode(result[0]),
            [ckb.molecule.Bytes.molecule_decode(e) for e in ckb.molecule.decode_dynvec(result[1])],
        )


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
    def __init__(self, lock: bytearray | None, input_type: bytearray | None, output_type: bytearray | None):
        self.lock = lock
        self.input_type = input_type
        self.output_type = output_type

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        return all([
            self.lock == other.lock,
            self.input_type == other.input_type,
            self.output_type == other.output_type,
        ])

    def json(self):
        return {
            'lock': f'0x{self.lock.hex()}' if self.lock else None,
            'input_type': f'0x{self.input_type.hex()}' if self.input_type else None,
            'output_type': f'0x{self.output_type.hex()}' if self.output_type else None,
        }

    def molecule(self):
        return ckb.molecule.encode_dynvec([
            ckb.molecule.Bytes(self.lock).molecule() if self.lock else bytearray(),
            ckb.molecule.Bytes(self.input_type).molecule() if self.input_type else bytearray(),
            ckb.molecule.Bytes(self.output_type).molecule() if self.output_type else bytearray(),
        ])

    @staticmethod
    def molecule_decode(data: bytearray):
        result = ckb.molecule.decode_dynvec(data)
        return WitnessArgs(
            ckb.molecule.Bytes.molecule_decode(result[0]) if result[0] else None,
            ckb.molecule.Bytes.molecule_decode(result[1]) if result[1] else None,
            ckb.molecule.Bytes.molecule_decode(result[2]) if result[2] else None,
        )
