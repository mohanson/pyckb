import typing

# byte array struct vector table option union

class Byte:
    def encode(n: int) -> bytearray:
        assert 0 <= n and n < 256
        return bytearray([n])

    def decode(d: bytearray) -> int:
        assert len(d) == 1
        return d[0]

class Array:
    def encode(f: typing.Callable, a: Dict) -> bytearray:
        r = bytearray()
        for e in a:
            r.extend(e.encode())

if __name__ == '__main__':
    assert Byte.encode(10) == bytearray([10])
    assert Byte.decode(Byte.encode(10)) == 10
