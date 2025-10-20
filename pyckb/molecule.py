# Doc: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0008-serialization/0008-serialization.md
import itertools
import struct
import typing


class U8:
    @classmethod
    def decode(cls, buffer: bytearray) -> int:
        return int.from_bytes(buffer, 'little')

    @classmethod
    def encode(cls, number: int) -> bytearray:
        assert number >= 0x00
        assert number <= 0xff
        return bytearray(number.to_bytes(1, 'little'))

    @classmethod
    def size(cls) -> int:
        return 1


class U16:
    @classmethod
    def decode(cls, buffer: bytearray) -> int:
        return int.from_bytes(buffer, 'little')

    @classmethod
    def encode(cls, number: int) -> bytearray:
        assert number >= 0x00
        assert number <= 0xffff
        return bytearray(number.to_bytes(2, 'little'))

    @classmethod
    def size(cls) -> int:
        return 2


class U32:
    @classmethod
    def decode(cls, buffer: bytearray) -> int:
        return int.from_bytes(buffer, 'little')

    @classmethod
    def encode(cls, number: int) -> bytearray:
        assert number >= 0x00
        assert number <= 0xffffffff
        return bytearray(number.to_bytes(4, 'little'))

    @classmethod
    def size(cls) -> int:
        return 4


class U64:
    @classmethod
    def decode(cls, buffer: bytearray) -> int:
        return int.from_bytes(buffer, 'little')

    @classmethod
    def encode(cls, number: int) -> bytearray:
        assert number >= 0x00
        assert number <= 0xffffffffffffffff
        return bytearray(number.to_bytes(8, 'little'))

    @classmethod
    def size(cls) -> int:
        return 8


class U128:
    @classmethod
    def decode(cls, buffer: bytearray) -> int:
        return int.from_bytes(buffer, 'little')

    @classmethod
    def encode(cls, number: int) -> bytearray:
        assert number >= 0x00
        assert number <= 0xffffffffffffffffffffffffffffffff
        return bytearray(number.to_bytes(16, 'little'))

    @classmethod
    def size(cls) -> int:
        return 16


class I8:
    @classmethod
    def decode(cls, buffer: bytearray) -> int:
        return int.from_bytes(buffer, 'little', signed=True)

    @classmethod
    def encode(cls, number: int) -> bytearray:
        assert number >= -0x80
        assert number <= +0x7f
        return bytearray(number.to_bytes(1, 'little', signed=True))

    @classmethod
    def size(cls) -> int:
        return 1


class I16:
    @classmethod
    def decode(cls, buffer: bytearray) -> int:
        return int.from_bytes(buffer, 'little', signed=True)

    @classmethod
    def encode(cls, number: int) -> bytearray:
        assert number >= -0x8000
        assert number <= +0x7fff
        return bytearray(number.to_bytes(2, 'little', signed=True))

    @classmethod
    def size(cls) -> int:
        return 2


class I32:
    @classmethod
    def decode(cls, buffer: bytearray) -> int:
        return int.from_bytes(buffer, 'little', signed=True)

    @classmethod
    def encode(cls, number: int) -> bytearray:
        assert number >= -0x80000000
        assert number <= +0x7fffffff
        return bytearray(number.to_bytes(4, 'little', signed=True))

    @classmethod
    def size(cls) -> int:
        return 4


class I64:
    @classmethod
    def decode(cls, buffer: bytearray) -> int:
        return int.from_bytes(buffer, 'little', signed=True)

    @classmethod
    def encode(cls, number: int) -> bytearray:
        assert number >= -0x8000000000000000
        assert number <= +0x7fffffffffffffff
        return bytearray(number.to_bytes(8, 'little', signed=True))

    @classmethod
    def size(cls) -> int:
        return 8


class I128:
    @classmethod
    def decode(cls, buffer: bytearray) -> int:
        return int.from_bytes(buffer, 'little', signed=True)

    @classmethod
    def encode(cls, number: int) -> bytearray:
        assert number >= -0x80000000000000000000000000000000
        assert number <= +0x7fffffffffffffffffffffffffffffff
        return bytearray(number.to_bytes(16, 'little', signed=True))

    @classmethod
    def size(cls) -> int:
        return 16


class F32:
    @classmethod
    def decode(cls, buffer: bytearray) -> float:
        return struct.unpack('<f', buffer)[0]

    @classmethod
    def encode(cls, number: float) -> bytearray:
        return bytearray(struct.pack('<f', number))

    @classmethod
    def size(cls) -> int:
        return 4


class F64:
    @classmethod
    def decode(cls, buffer: bytearray) -> float:
        return struct.unpack('<d', buffer)[0]

    @classmethod
    def encode(cls, number: float) -> bytearray:
        return bytearray(struct.pack('<d', number))

    @classmethod
    def size(cls) -> int:
        return 8


class Array:
    def __init__(self, kype: typing.Any, size: int) -> None:
        self.kype = kype
        self.lens = size

    def decode(self, buffer: bytearray) -> typing.List:
        assert isinstance(buffer, bytearray)
        return [self.kype.decode(bytearray(e)) for e in itertools.batched(buffer, self.kype.size())]

    def encode(self, pylist: typing.List) -> bytearray:
        assert len(pylist) == self.lens
        return bytearray(itertools.chain(*[self.kype.encode(e) for e in pylist]))

    def size(self) -> int:
        return self.kype.size() * self.lens


class Struct:
    def __init__(self, kype: typing.List) -> None:
        self.kype = kype

    def decode(self, buffer: bytearray) -> typing.List:
        r = []
        s = 0
        for e in self.kype:
            r.append(e.decode(buffer[s:s+e.size()]))
            s += e.size()
        return r

    def encode(self, pylist: typing.List) -> bytearray:
        r = bytearray()
        for e in zip(self.kype, pylist):
            r.extend(e[0].encode(e[1]))
        return r


class Slice:
    def __init__(self, kype: typing.Any) -> None:
        assert hasattr(kype, 'size')
        self.kype = kype

    def decode(self, buffer: bytearray) -> typing.List:
        assert isinstance(buffer, bytearray)
        return [self.kype.decode(bytearray(e)) for e in itertools.batched(buffer[4:], self.kype.size())]

    def encode(self, pylist: typing.List) -> bytearray:
        body = bytearray(itertools.chain(*[self.kype.encode(e) for e in pylist]))
        head = U32.encode(len(pylist))
        return head + body


class Split:
    @classmethod
    def decode(cls, buffer: bytearray) -> typing.List[bytearray]:
        assert len(buffer) >= 4
        assert len(buffer) == U32.decode(buffer[:4])
        if len(buffer) == 4:
            return []
        nums = U32.decode(buffer[4:8]) // 4 - 1
        head = []
        for i in range(nums):
            head.append(U32.decode(buffer[i * 4 + 4: i * 4 + 8]))
        head.append(len(buffer))
        body = []
        for i in range(nums):
            body.append(buffer[head[i]:head[i+1]])
        return body

    @classmethod
    def encode(cls, pylist: typing.List[bytearray]) -> bytearray:
        head = bytearray()
        body = bytearray()
        head_size = 4 + 4 * len(pylist)
        body_size = 0
        for item in pylist:
            size = head_size + body_size
            head.extend(U32.encode(size))
            body.extend(item)
            body_size += len(item)
        size = head_size + body_size
        return U32.encode(size) + head + body


class Scale:
    def __init__(self, kype: typing.Any) -> None:
        self.kype = kype

    def decode(self, buffer: bytearray) -> typing.List:
        return [self.kype.decode(e) for e in Split.decode(buffer)]

    def encode(self, pylist: typing.List) -> bytearray:
        return Split.encode([self.kype.encode(e) for e in pylist])


class Table:
    def __init__(self, kype: typing.List) -> None:
        self.kype = kype

    def decode(self, buffer: bytearray) -> typing.List:
        return [e[0].decode(e[1]) for e in zip(self.kype, Split.decode(buffer))]

    def encode(self, pylist: typing.List) -> bytearray:
        return Split.encode([e[0].encode(e[1]) for e in zip(self.kype, pylist)])


class Option:
    def __init__(self, kype: typing.Any) -> None:
        self.kype = kype

    def decode(self, buffer: bytearray) -> typing.Optional[typing.Any]:
        return self.kype.decode(buffer) if len(buffer) > 0x00 else None

    def encode(self, pydata: typing.Optional[typing.Any]) -> bytearray:
        return self.kype.encode(pydata) if pydata is not None else bytearray()


class Enum:
    @classmethod
    def decode(cls, buffer: bytearray) -> int:
        return U32.decode(buffer)

    @classmethod
    def encode(cls, number: int) -> bytearray:
        return U32.encode(number)


class Custom:
    def __init__(self, size: int) -> None:
        self.lens = size

    def decode(self, buffer: bytearray) -> bytearray:
        return buffer

    def encode(self, buffer: bytearray) -> bytearray:
        return buffer

    def size(self) -> int:
        assert self.lens != 0
        return self.lens


Byte = U8
Byte10 = Custom(10)
Byte32 = Custom(32)


class Bytes:
    @classmethod
    def decode(cls, buffer: bytearray) -> bytearray:
        assert U32.decode(buffer[:4]) == len(buffer) - 4
        return buffer[4:]

    @classmethod
    def encode(cls, buffer: bytearray) -> bytearray:
        return U32.encode(len(buffer)) + buffer
