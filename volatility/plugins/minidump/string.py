import struct

class MINIDUMP_STRING(object):
    def __init__(self, str):
        self.str = str
    
    def to_bytes(self):
        t = struct.pack('<I', len(self.str) * 2)
        t += self.str.encode('utf-16')
    
