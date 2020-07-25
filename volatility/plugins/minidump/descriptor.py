import struct

# wrapper of MINIDUMP_LOCATION_DESCRIPTOR
class MiniDumpLocationDescriptor:
    def __init__(self):
        self.DataSize = 0
        self.RVA = 0
    
    def size(self):
        return self.DataSize
    
    def setSize(self, value):
        self.DataSize = value
    
    def setRVA(self, value):
        self.RVA = value
    
    def to_bytes(self):
        r = struct.pack('<I', self.DataSize)
        r += struct.pack('<I', self.RVA)
        return r

    @classmethod
    def create(cls, size, rva):
        x = cls()
        x.setSize(size)
        x.setRVA(rva)
        return x


# wrapper of MINIDUMP_LOCATION_DESCRIPTOR64
class MiniDumpLocation64(MiniDumpLocationDescriptor):
    def __init__(self):
        MiniDumpLocationDescriptor.__init__(self)

    @classmethod
    def create(cls, size, rva):
        x = cls()
        x.setSize(size)
        x.setRVA(rva)
        
    def to_bytes(self):
        r = struct.pack('<Q', self.DataSize)
        r+= struct.pack('<Q', self.RVA)

