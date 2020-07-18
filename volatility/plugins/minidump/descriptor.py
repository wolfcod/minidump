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
        r = self.DataSize.to_bytes(4, byteorder = 'little', signed = False)
        r += self.RVA.to_bytes(4, byteorder = 'little', signed = False)
        return r

# wrapper of MINIDUMP_LOCATION_DESCRIPTOR64
class MiniDumpLocation64(MiniDumpLocationDescriptor):
    def __init__(self):
        MiniDumpLocationDescriptor.__init__(self)

    def to_bytes(self):
        r = self.DataSize.to_bytes(8, byteorder='little', signed = False)
        r+= self.RVA.to_bytes(8, byteorder='little', signed = False)

