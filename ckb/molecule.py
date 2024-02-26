# Doc: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0008-serialization/0008-serialization.md


def decode_dynvec(data: bytearray):
    assert len(data) >= 4
    assert len(data) == int.from_bytes(data[0:4], 'little')
    nums = int.from_bytes(data[4:8], 'little') // 4 - 1
    head = []
    for i in range(nums):
        head.append(int.from_bytes(data[i * 4 + 4: i * 4 + 8], 'little'))
    head.append(len(data))
    body = []
    for i in range(nums):
        body.append(data[head[i]:head[i+1]])
    return body


def decode_fixvec(data: bytearray):
    assert len(data) >= 4
    icnt = int.from_bytes(data[0:4], 'little')
    body = []
    if icnt > 0:
        size = len(data[4:]) // icnt
        for i in range(icnt):
            body.append(data[4+i*size:4+i*size+size])
    return body


def decode_seq(data: bytearray, size: list[int]):
    r = []
    s = 0
    for n in size:
        r.append(data[s:s+n])
        s += n
    return r


def encode_dynvec(data: list[bytearray]):
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


def encode_fixvec(data: list[bytearray]):
    r = bytearray()
    r.extend(len(data).to_bytes(4, 'little'))
    for e in data:
        r.extend(e)
    return r


def encode_seq(data: list[bytearray]):
    r = bytearray()
    for e in data:
        r.extend(e)
    return r


class Byte:
    def __init__(self, data: int):
        assert 0 <= data and data <= 0xff
        self.data = data

    def __eq__(self, other):
        a = self.data == other.data
        return a

    @staticmethod
    def molecule_read(data: bytearray):
        assert len(data) == 1
        return data[0]

    @staticmethod
    def molecule_size():
        return 1

    def molecule(self):
        return bytearray([self.data])


class Byte32:
    def __init__(self, data: bytearray):
        assert len(data) == 32
        self.data = data

    def __eq__(self, other):
        a = self.data == other.data
        return a

    @staticmethod
    def molecule_read(data: bytearray):
        return data

    @staticmethod
    def molecule_size():
        return 32

    def molecule(self):
        return self.data


class Bytes:
    def __init__(self, data: bytearray):
        self.data = data

    def __eq__(self, other):
        a = self.data == other.data
        return a

    @staticmethod
    def molecule_read(data: bytearray):
        l = int.from_bytes(data[:4], 'little')
        assert l == len(data) - 4
        return data[4:]

    def molecule(self):
        r = bytearray()
        r.extend(len(self.data).to_bytes(4, 'little'))
        r.extend(self.data)
        return r


class U32:
    def __init__(self, data: int):
        assert 0 <= data and data <= 0xffffffff
        self.data = data

    def __eq__(self, other):
        a = self.data == other.data
        return a

    @staticmethod
    def molecule_read(data: bytearray):
        return int.from_bytes(data, 'little')

    @staticmethod
    def molecule_size():
        return 4

    def molecule(self):
        return self.data.to_bytes(4, 'little')


class U64:
    def __init__(self, data: int):
        assert 0 <= data and data <= 0xffffffffffffffff
        self.data = data

    def __eq__(self, other):
        a = self.data == other.data
        return a

    @staticmethod
    def molecule_read(data: bytearray):
        return int.from_bytes(data, 'little')

    @staticmethod
    def molecule_size():
        return 8

    def molecule(self):
        return self.data.to_bytes(8, 'little')
