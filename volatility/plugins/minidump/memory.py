import struct

from . import descriptor
from descriptor import MiniDumpLocationDescriptor

class MINIDUMP_MEMORY_INFO:
    def __init__(self):
        self.BaseAddress = 0
        self.AllocationBase = 0
        self.AllocationProtect = 0
        self.RegionSize = 0
        self.State = 0
        self.Protect = 0
        self.Type = 0
    
    def to_bytes(self):
        t = struct.pack('<Q', self.BaseAddress)
        t += struct.pack('<Q', self.AllocationBase)
        t += struct.pack('<I', self.AllocationProtect)
        t += struct.pack('I', 0) # alignment1
        t += struct.pack('<Q', self.RegionSize)
        t += struct.pack('<I', self.State)
        t += struct.pack('<I', self.Protect)
        t += struct.pack('<I', self.Type)
        t += struct.pack('I', 0) # alignment2

        return t

    @classmethod
    def create(cls, BaseAddress, AllocationBase, AllocationProtect, RegionSize, State, Protect, Type):
        x = cls()
        x.BaseAddress = BaseAddress
        x.AllocationBase = AllocationBase
        x.AllocationProtect = AllocationProtect
        x.RegionSize = RegionSize
        x.State = State
        x.Protect = Protect
        x.Type = Type
        return x
    
    @classmethod
    def sizeof(cls):
        return 48 # sizeof(MEMORY_TYPE_INFO)

class MemoryInfoListStream:
    def __init__(self):
        self.descriptors = []

    def to_bytes(self):
        t = struct.pack('<I', 16) # sizeof MINIDUMP_MEMORY_INFO_LIST
        t += struct.pack('<I', MINIDUMP_MEMORY_INFO.sizeof())
        t += struct.pack('<I', len(self.descriptors))

        for desc in self.descriptors:
            t += desc.to_bytes()
        
        return t

    def add_va(self, BaseAddress, AllocationBase, AllocationProtect, RegionSize, State, Protect, Type):
        self.descriptors.append(MINIDUMP_MEMORY_INFO.create(BaseAddress, AllocationBase, AllocationProtect, RegionSize, State, Protect, Type))

class MemoryStream:

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
