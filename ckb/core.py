import hashlib
import ckb.secp256k1


def hash(data: bytearray):
    return bytearray(hashlib.blake2b(data, digest_size=32, person=b'ckb-default-hash').digest())


class PriKey:
    def __init__(self, n: int):
        self.n = n

    def __repr__(self):
        return f'PriKey({self.n:064x})'

    def pubkey(self):
        pubkey = ckb.secp256k1.G * ckb.secp256k1.Fr(self.n)
        return PubKey(pubkey.x.x, pubkey.y.x)


class PubKey:
    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y

    def __repr__(self):
        return f'PubKey({self.x:064x}, {self.y:064x})'

    @staticmethod
    def read(data: bytearray):
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
    prikey = PriKey(0xd5d8fe30c6ab6bfd2c6e0a940299a1e01a9ab6b8a8ed407a00b130e6a51435fc)
    pubkey = prikey.pubkey()
    assert pubkey.x == 0x97202631ccab00b8669e0b1fcc376f082513f22593c5e99fbf76ab02e8911d2e
    assert pubkey.y == 0xeae37bf649d45e0cf83c5c057de60d685ece29e9b7e58959a638845d3d0659c6
    assert pubkey.pack().hex() == '0297202631ccab00b8669e0b1fcc376f082513f22593c5e99fbf76ab02e8911d2e'
    pubkey = PubKey.read(pubkey.pack())
    assert pubkey.pack().hex() == '0297202631ccab00b8669e0b1fcc376f082513f22593c5e99fbf76ab02e8911d2e'
    assert hash(pubkey.pack())[:20].hex() == 'e5126d9d897e5d5249607760f9da024119f9e296'


class Script:
    def __init__(self, code_hash: bytearray, hash_type: int, args: bytearray):
        assert len(code_hash) == 32
        assert hash_type < 3  # 0 => data, 1 => type, 2 => data1
        self.code_hash = code_hash
        self.hash_type = hash_type
        self.args = args

    def __repr__(self):
        return f'Script(code_hash={self.code_hash.hex()}, hash_type={self.hash_type}, args={self.args.hex()})'
