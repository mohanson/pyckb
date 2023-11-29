
# byte array struct vector table option union

class Byte:
    def __init__(self, b: int):
        assert 0 <= self.b and self.b < 256
        self.b = b

    def pack(self):
        return bytearray([self.b])

class Array:
    def __init__(self, data):
        pass

import json
json.loads
