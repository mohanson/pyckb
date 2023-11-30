import ckb.bech32
import ckb.config
import ckb.secp256k1
import hashlib
import struct


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
        assert len(data) == struct.unpack('<I', data[0:4])[0]
        code_hash = data[16:48]
        hash_type = data[48]
        args_size = struct.unpack('<I', data[49:53])[0]
        args = data[53:53+args_size]
        return Script(code_hash, hash_type, args)

    def pack(self):
        head = bytearray()
        body = bytearray()
        head_size = 4 + 3 * 4
        n = head_size + len(self.code_hash) + 1 + 4 + len(self.args)
        head.extend(struct.pack('<I', n))
        n = head_size
        head.extend(struct.pack('<I', n))
        body.extend(self.code_hash)
        n = n + len(self.code_hash)
        head.extend(struct.pack('<I', n))
        body.append(self.hash_type)
        n = n + 1
        head.extend(struct.pack('<I', n))
        body.extend(struct.pack('<I', len(self.args)))
        body.extend(self.args)
        return head + body

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
        return OutPoint(data[0x00:0x20], struct.unpack('<I', data[0x20:0x24])[0])

    def pack(self):
        r = bytearray()
        r.extend(self.tx_hash)
        r.extend(struct.pack('<I', self.index))
        return r

    def json(self):
        return {
            'tx_hash': '0x' + self.tx_hash.hex(),
            'index': hex(self.index),
        }


if __name__ == '__main__':
    out_point = OutPoint(
        ckb.config.current.scripts.secp256k1_blake160.out_point.tx_hash,
        ckb.config.current.scripts.secp256k1_blake160.out_point.index,
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
            struct.unpack('<Q', data[:8])[0],
            OutPoint.read(data[8:44])
        )

    def pack(self):
        r = bytearray()
        r.extend(struct.pack('<Q', self.since))
        r.extend(self.previous_output.pack())
        return r

    def json(self):
        return {
            'since': hex(self.since),
            'previous_output': self.previous_output.json()
        }


if __name__ == '__main__':
    out_point = OutPoint(
        ckb.config.current.scripts.secp256k1_blake160.out_point.tx_hash,
        ckb.config.current.scripts.secp256k1_blake160.out_point.index,
    )
    cell_input = CellInput(42, out_point)
    assert CellInput.read(cell_input.pack()) == cell_input

# table CellOutput {
#     capacity:       Uint64,
#     lock:           Script,
#     type_:          ScriptOpt,
# }

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
