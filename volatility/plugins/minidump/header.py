class MiniDumpHeader:
    def __init__(self):
        self.Signature = 0
        self.Version = 0
        self.NumberOfStreams = 0
        self.StreamDirectoryRva = 0
        self.Checksum = 0
        self.TimeStampDate = 0
        self.Flags = 0
    
    def to_bytes(self):
        t = self.Signature.to_bytes(4, byteorder='little', signed = False)
        t += self.Version.to_bytes(4, byteorder='little', signed = False)
        t += self.NumberOfStreams.to_bytes(4, byteorder='little', signed=False)
        t += self.StreamDirectoryRva.to_bytes(4, byteorder='little', signed=False)
        t += self.Checksum.to_bytes(4, byteorder='little', signed=False)
        t += self.TimeStampDate.to_bytes(4, byteorder='little', signed=False)
        t += self.Flags.to_bytes(8, byteorder='little', signed=False)

    def __str__(self):
        return "MiniDumpHeader object"
 
    