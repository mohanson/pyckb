import ckb.bech32
import ckb.config
import ckb.secp256k1
import hashlib
import io
import typing


def hash(data: bytearray):
    return bytearray(hashlib.blake2b(data, digest_size=32, person=b'ckb-default-hash').digest())


class PriKey:
    def __init__(self, n: int):
        self.n = n

    def __repr__(self):
        return f'PriKey(n={self.n:064x})'

    def __eq__(self, other):
        a = self.n == other.n
        return a

    @staticmethod
    def read(data: bytearray):
        assert len(data) == 32
        return Prikey(int.from_bytes(data, byteorder='big'))

    def pack(self):
        return bytearray(self.n.to_bytes(32, byteorder='big'))

    def pubkey(self):
        pubkey = ckb.secp256k1.G * ckb.secp256k1.Fr(self.n)
        return PubKey(pubkey.x.x, pubkey.y.x)


class PubKey:
    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y

    def __repr__(self):
        return f'PubKey(x={self.x:064x}, y={self.y:064x})'

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


if __name__ == '__main__':
    # Double checked by https://ckb.tools/generator
    prikey = PriKey(0x0000000000000000000000000000000000000000000000000000000000000001)
    pubkey = prikey.pubkey()
    assert pubkey.x == 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    assert pubkey.y == 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    assert pubkey.pack().hex() == '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    assert PubKey.read(pubkey.pack()) == pubkey
    assert hash(pubkey.pack())[:20].hex() == '75178f34549c5fe9cd1a0c57aebd01e7ddf9249e'


class Script:
    def __init__(self, code_hash: bytearray, hash_type: int, args: bytearray):
        assert len(code_hash) == 32
        assert hash_type < 3  # 0 => data, 1 => type, 2 => data1
        self.code_hash = code_hash
        self.hash_type = hash_type
        self.args = args

    def __repr__(self):
        return f'Script(code_hash={self.code_hash.hex()}, hash_type={self.hash_type}, args={self.args.hex()})'

    def __eq__(self, other):
        a = self.code_hash == other.code_hash
        b = self.hash_type == other.hash_type
        c = self.args == other.args
        return a and b and c

    @staticmethod
    def read(data: bytearray):
        assert len(data) >= 4
        assert len(data) == int.from_bytes(data[0:4], 'little')
        reader = io.BytesIO(data[4 + 3 * 4:])
        code_hash = bytearray(reader.read(32))
        hash_type = int(reader.read(1)[0])
        args_size = int.from_bytes(reader.read(4), 'little')
        args = bytearray(reader.read(args_size))
        return Script(code_hash, hash_type, args)

    def pack(self):
        line = []
        line.append(self.code_hash)
        line.append(bytearray([self.hash_type]))
        line.append(bytearray(len(self.args).to_bytes(4, 'little')) + self.args)
        head = bytearray()
        body = bytearray()
        head_size = 4 + 4 * len(line)
        body_size = 0
        for data in line:
            head.extend((head_size + body_size).to_bytes(4, 'little'))
            body.extend(data)
            body_size += len(data)
        return (head_size + body_size).to_bytes(4, 'little') + head + body

    def json(self):
        return {
            'code_hash': '0x' + self.code_hash.hex(),
            'hash_type': {
                0: 'data',
                1: 'type',
                2: 'data1'
            }[self.hash_type],
            'args': '0x' + self.args.hex(),
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
        return f'OutPoint(tx_hash={self.tx_hash.hex()}, index={self.index})'

    def __eq__(self, other):
        a = self.tx_hash == other.tx_hash
        b = self.index == other.index
        return a and b

    @staticmethod
    def read(data: bytearray):
        assert len(data) == 36
        return OutPoint(data[0x00:0x20], int.from_bytes(data[0x20:0x24], 'little'))

    def pack(self):
        r = bytearray()
        r.extend(self.tx_hash)
        r.extend(self.index.to_bytes(4, 'little'))
        return r

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
        return f'CellInput(since={self.since}, previous_output={self.previous_output})'

    def __eq__(self, other):
        a = self.since == other.since
        b = self.previous_output == other.previous_output
        return a and b

    @staticmethod
    def read(data: bytearray):
        assert len(data) == 44
        return CellInput(
            int.from_bytes(data[:8], 'little'),
            OutPoint.read(data[8:44])
        )

    def pack(self):
        r = bytearray()
        r.extend(self.since.to_bytes(8, 'little'))
        r.extend(self.previous_output.pack())
        return r

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
        return f'CellOutput(capacity={self.capacity}, lock={self.lock}, type={self.type})'

    def __eq__(self, other):
        a = self.capacity == other.capacity
        b = self.lock == other.lock
        c = self.type == other.type
        return a and b and c

    @staticmethod
    def read(data: bytearray):
        assert len(data) >= 4
        assert len(data) == int.from_bytes(data[0:4], 'little')
        reader = io.BufferedReader(io.BytesIO(data[4 + 4 * 3:]))
        capacity = int.from_bytes(reader.read(8), 'little')
        size = int.from_bytes(reader.peek(4)[:4], 'little')
        lock = Script.read(reader.read(size))
        if reader.peek(1)[0]:
            size = int.from_bytes(reader.peek(4)[:4], 'little')
            type = Script.read(reader.read(size))
        else:
            type = None
        return CellOutput(capacity, lock, type)

    def pack(self):
        line = []
        line.append(self.capacity.to_bytes(8, 'little'))
        line.append(self.lock.pack())
        line.append(self.type.pack() if self.type else bytearray([0]))
        head = bytearray()
        body = bytearray()
        head_size = 4 + 4 * len(line)
        body_size = 0
        for data in line:
            head.extend((head_size + body_size).to_bytes(4, 'little'))
            body.extend(data)
            body_size += len(data)
        return (head_size + body_size).to_bytes(4, 'little') + head + body

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

# struct CellDep {
#     out_point:      OutPoint,
#     dep_type:       byte,
# }

# table RawTransaction {
#     version:        Uint32,
#     cell_deps:      CellDepVec,
#     header_deps:    Byte32Vec,
#     inputs:         CellInputVec,
#     outputs:        CellOutputVec,
#     outputs_data:   BytesVec,
# }

# table Transaction {
#     raw:            RawTransaction,
#     witnesses:      BytesVec,
# }

# struct RawHeader {
#     version:                Uint32,
#     compact_target:         Uint32,
#     timestamp:              Uint64,
#     number:                 Uint64,
#     epoch:                  Uint64,
#     parent_hash:            Byte32,
#     transactions_root:      Byte32,
#     proposals_hash:         Byte32,
#     extra_hash:             Byte32,
#     dao:                    Byte32,
# }

# struct Header {
#     raw:                    RawHeader,
#     nonce:                  Uint128,
# }

# table UncleBlock {
#     header:                 Header,
#     proposals:              ProposalShortIdVec,
# }

# table Block {
#     header:                 Header,
#     uncles:                 UncleBlockVec,
#     transactions:           TransactionVec,
#     proposals:              ProposalShortIdVec,
# }

# table BlockV1 {
#     header:                 Header,
#     uncles:                 UncleBlockVec,
#     transactions:           TransactionVec,
#     proposals:              ProposalShortIdVec,
#     extension:              Bytes,
# }

# table CellbaseWitness {
#     lock:    Script,
#     message: Bytes,
# }

# table WitnessArgs {
#     lock:                   BytesOpt,          // Lock args
#     input_type:             BytesOpt,          // Type args for input
#     output_type:            BytesOpt,          // Type args for output
# }
