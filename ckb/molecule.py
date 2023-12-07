# Doc: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0008-serialization/0008-serialization.md


class Byte:
    def __init__(self, data):
        assert 0 <= data and data <= 0xff
        self.data = data

    def molecule(self):
        return bytearray([self.data])


class Byte32:
    def __init__(self, data):
        assert len(data) == 32
        self.data = data

    @staticmethod
    def molecule_read(data: bytearray):
        return data

    def molecule(self):
        return self.data


class Bytenn:
    def __init__(self, data):
        self.data = data

    @staticmethod
    def molecule_read(data: bytearray):
        return data[4:]

    def molecule(self):
        r = bytearray()
        r.extend(len(self.data).to_bytes(4, 'little'))
        r.extend(self.data)
        return r


class Dynvec:
    def __init__(self, data):
        self.data = data

    @staticmethod
    def molecule_read(data: bytearray):
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

    def molecule(self):
        line = [e.molecule() for e in self.data]
        head = bytearray()
        body = bytearray()
        head_size = 4 + 4 * len(line)
        body_size = 0
        for data in line:
            size = head_size + body_size
            head.extend(bytearray(size.to_bytes(4, 'little')))
            body.extend(data)
            body_size += len(data)
        size = head_size + body_size
        return bytearray(size.to_bytes(4, 'little')) + head + body


class Fixvec:
    def __init__(self, data):
        self.data = data

    @staticmethod
    def molecule_read(data: bytearray):
        assert len(data) >= 4
        icnt = int.from_bytes(data[0:4], 'little')
        body = []
        if icnt > 0:
            size = len(data[4:]) // icnt
            for i in range(icnt):
                body.append(data[4+i*size:4+i*size+size])
        return body

    def molecule(self):
        r = bytearray()
        r.extend(len(self.data).to_bytes(4, 'little'))
        for e in self.data:
            r.extend(e.molecule())
        return r


class Option:
    def __init__(self, data):
        self.data = data

    def molecule(self):
        return self.data.molecule() if self.data else bytearray()


class Struct:
    def __init__(self, data):
        self.data = data

    def molecule(self):
        r = bytearray()
        for e in self.data:
            r.extend(e.molecule())
        return r


class U32:
    def __init__(self, data):
        assert 0 <= data and data <= 0xffffffff
        self.data = data

    @staticmethod
    def molecule_read(data: bytearray):
        return int.from_bytes(data, 'little')

    def molecule(self):
        return self.data.to_bytes(4, 'little')


class U64:
    def __init__(self, data):
        assert 0 <= data and data <= 0xffffffffffffffff
        self.data = data

    @staticmethod
    def molecule_read(data: bytearray):
        return int.from_bytes(data, 'little')

    def molecule(self):
        return self.data.to_bytes(8, 'little')
