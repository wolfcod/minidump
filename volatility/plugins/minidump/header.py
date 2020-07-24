import struct

class MiniDumpHeader:
    def __init__(self):
        self.Signature = 'MDMP'
        # MINIDUMP_VERSION and two bytes as 00 00
        self.Version = 42899 
        self.NumberOfStreams = 0
        self.StreamDirectoryRva = 0
        self.Checksum = 0
        self.TimeStampDate = 0
        self.Flags = 0
    
    def getNumberOfStreams(self):
        return self.NumberOfStreams

    def to_bytes(self):
        t = self.Signature.encode('ascii')
        t += struct.pack('<I', self.Version)
        t += struct.pack('<I', self.NumberOfStreams)
        t += struct.pack('<I', self.StreamDirectoryRva)
        t += struct.pack('<I', self.Checksum)
        t += struct.pack('<I',self.TimeStampDate)
        t += struct.pack('<Q',self.Flags)

        return t

    def __str__(self):
        return "MiniDumpHeader object"
 
    