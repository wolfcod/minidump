from . import descriptor
from descriptor import MiniDumpLocationDescriptor

class MemoryStream(object):

    def __init__(self, va, size, data):
        self.va = va
        self.size = size
        self.data = data
    
    @classmethod
    def from_data(cls, va, size, data):
        return cls(va, size, data)

    @classmethod
    def zero_data(cls, va, size):
        b = '\x00' * size
        return cls(va, size, b)
    
    def __eq__(self, other):
        return self.va == other.va

    def __lt__(self, other):
        return self.va < other.va

    def __gt__(self, other):
        return self.va > other.va

    def to_bytes(self):
        return self.data

    def length(self):
        return self.size
        
    # return a MiniDumpLocationDescriptor with right rva
    def getDescriptor(self, rva):
        T = MiniDumpLocationDescriptor.create(self.size, rva)
        return T
