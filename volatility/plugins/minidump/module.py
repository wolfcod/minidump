import struct

from . import descriptor
from descriptor import MiniDumpLocationDescriptor

class VS_FIXEDFILEINFO(object):
    def __init__(self):
        self.dwSignature = 0
        self.dwStrucVersion = 0
        self.dwFileVersionMS = 0
        self.dwFileVersionLS = 0
        self.dwProductVersionMS = 0
        self.dwProductVersionLS = 0
        self.dwFileFlagsMask = 0
        self.dwFileFlags = 0
        self.dwFileOS = 0
        self.dwFileType = 0
        self.dwFileSubtype = 0
        self.dwFileDateMS = 0
        self.dwFileDateLS = 0
    
    def to_bytes(self):
        t = struct.pack('<I', self.dwSignature)
        t += struct.pack('<I', self.dwStrucVersion)
        t += struct.pack('<I', self.dwFileVersionMS)
        t += struct.pack('<I', self.dwFileVersionLS
        t += struct.pack('<I', self.dwProductVersionMS)
        t += struct.pack('<I', self.dwProductVersionLS)
        t += struct.pack('<I', self.dwFileFlagsMask)
        t += struct.pack('<I', self.dwFileFlags)
        t += struct.pack('<I', self.dwFileOS)
        t += struct.pack('<I', self.dwFileType)
        t += struct.pack('<I', self.dwFileSubtype)
        t += struct.pack('<I', self.dwFileDateMS)
        t += struct.pack('<I', self.dwFileDateLS)

class MINIDUMP_MODULE(object):
    def __init__(self):
        self.BaseOfImage = 0
        self.SizeOfImage = 0
        self.CheckSum = 0
        self.TimeDateStamp = 0
        self.ModuleNameRva = 0
        self.VersionInfo = VS_FIXEDFILEINFO()
        self.CvRecord =  MiniDumpLocationDescriptor()
        self.MiscRecord = MiniDumpLocationDescriptor()

        self.Reserved0 = 0
        self.Reserved1 = 0
    
    def to_bytes(self):
        t = struct.pack('<Q', self.BaseOfImage)
        t += struct.pack('<I', self.SizeOfImage)
        t += struct.pack('<I', self.CheckSum)
        t += struct.pack('<I', self.TimeDateStamp)
        t += struct.pack('<I', self.ModuleNameRva)
        t += self.VersionInfo.to_bytes()
        t += self.CvRecord.to_bytes()
        t += self.MiscRecord.to_bytes()

        t += struct.pack('QQ', self.Reserved0, self.Reserved1) # alignment2

        return t

    @classmethod
    def create(cls, BaseOfImage, SizeOfImage, CheckSum, TimeDateStamp, ModuleNameRva):
        x = cls()
        x.BaseOfImage = BaseOfImage
        x.SizeOfImage = SizeOfImage
        x.CheckSum = CheckSum
        x.TimeDateStamp = TimeDateStamp
        x.ModuleNameRva = ModuleNameRva
        return x
    
    @classmethod
    def sizeof(cls):
        return 48 # sizeof(MEMORY_TYPE_INFO)

class MemoryInfoListStream(object):
    def __init__(self):
        self.descriptors = []

    def to_bytes(self):
        t = struct.pack('<I', 16) # sizeof MINIDUMP_MEMORY_INFO_LIST
        t += struct.pack('<I', MINIDUMP_MEMORY_INFO.sizeof())
        t += struct.pack('<I', len(self.descriptors))

        for desc in descriptors:
            t += desc.to_bytes()
        
        return t
        
    def add_va(self, BaseAddress, AllocationBase, AllocationProtect, RegionSize, State, Protect, Type):
        self.descriptors.add(MINIDUMP_MEMORY_INFO.create(BaseAddress, AllocationBase, AllocationProtect, RegionSize, State, Protect, Type))

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
