# Doc: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0008-serialization/0008-serialization.md
import typing
Self = typing.Self


def decode_dynvec(data: bytearray) -> typing.List[bytearray]:
    assert len(data) >= 4
    assert len(data) == int.from_bytes(data[0:4], 'little')
    if len(data) == 4:
        return []
    nums = int.from_bytes(data[4:8], 'little') // 4 - 1
    head = []
    for i in range(nums):
        head.append(int.from_bytes(data[i * 4 + 4: i * 4 + 8], 'little'))
    head.append(len(data))
    body = []
    for i in range(nums):
        body.append(data[head[i]:head[i+1]])
    return body


def decode_fixvec(data: bytearray) -> typing.List[bytearray]:
    assert len(data) >= 4
    icnt = int.from_bytes(data[0:4], 'little')
    body = []
    if icnt > 0:
        size = len(data[4:]) // icnt
        for i in range(icnt):
            body.append(data[4+i*size:4+i*size+size])
    return body


def decode_seq(data: bytearray, size: list[int]) -> typing.List[bytearray]:
    r = []
    s = 0
    for n in size:
        r.append(data[s:s+n])
        s += n
    return r


def encode_dynvec(data: list[bytearray]) -> bytearray:
    head = bytearray()
    body = bytearray()
    head_size = 4 + 4 * len(data)
    body_size = 0
    for item in data:
        size = head_size + body_size
        head.extend(bytearray(size.to_bytes(4, 'little')))
        body.extend(item)
        body_size += len(item)
    size = head_size + body_size
    return bytearray(size.to_bytes(4, 'little')) + head + body


def encode_fixvec(data: list[bytearray]) -> bytearray:
    r = bytearray()
    r.extend(len(data).to_bytes(4, 'little'))
    for e in data:
        r.extend(e)
    return r


def encode_seq(data: list[bytearray]) -> bytearray:
    r = bytearray()
    for e in data:
        r.extend(e)
    return r


class Byte:
    def __init__(self, data: int) -> None:
        assert 0 <= data and data <= 0xff
        self.data = data

    def __eq__(self, other) -> bool:
        return self.data == other.data

    def molecule(self) -> bytearray:
        return bytearray([self.data])

    @classmethod
    def molecule_decode(cls, data: bytearray) -> int:
        assert len(data) == 1
        return data[0]

    @classmethod
    def molecule_size(cls) -> int:
        return 1


class Byte32:
    def __init__(self, data: bytearray) -> None:
        assert len(data) == 32
        self.data = data

    def __eq__(self, other) -> bool:
        return self.data == other.data

    def molecule(self) -> bytearray:
        return self.data

    @classmethod
    def molecule_decode(cls, data: bytearray) -> bytearray:
        return data

    @classmethod
    def molecule_size(cls) -> int:
        return 32


class Bytes:
    def __init__(self, data: bytearray) -> None:
        self.data = data

    def __eq__(self, other) -> bool:
        return self.data == other.data

    def molecule(self) -> bytearray:
        r = bytearray()
        r.extend(len(self.data).to_bytes(4, 'little'))
        r.extend(self.data)
        return r

    @classmethod
    def molecule_decode(cls, data: bytearray) -> bytearray:
        l = int.from_bytes(data[:4], 'little')
        assert l == len(data) - 4
        return data[4:]


class U32:
    def __init__(self, data: int) -> None:
        assert 0 <= data and data <= 0xffffffff
        self.data = data

    def __eq__(self, other) -> bool:
        return self.data == other.data

    def molecule(self) -> bytearray:
        return self.data.to_bytes(4, 'little')

    @classmethod
    def molecule_decode(cls, data: bytearray) -> int:
        return int.from_bytes(data, 'little')

    @classmethod
    def molecule_size(cls) -> int:
        return 4


class U64:
    def __init__(self, data: int) -> None:
        assert 0 <= data and data <= 0xffffffffffffffff
        self.data = data

    def __eq__(self, other) -> bool:
        return self.data == other.data

    def molecule(self) -> bytearray:
        return self.data.to_bytes(8, 'little')

    @classmethod
    def molecule_decode(cls, data: bytearray) -> int:
        return int.from_bytes(data, 'little')

    @classmethod
    def molecule_size(cls) -> int:
        return 8


class U128:
    def __init__(self, data: int) -> None:
        assert 0 <= data and data <= 0xffffffffffffffffffffffffffffffff
        self.data = data

    def __eq__(self, other) -> bool:
        return self.data == other.data

    def molecule(self) -> bytearray:
        return self.data.to_bytes(16, 'little')

    @classmethod
    def molecule_decode(cls, data: bytearray) -> int:
        return int.from_bytes(data, 'little')

    @classmethod
    def molecule_size(cls) -> int:
        return 16
