import os
import struct

from . import *
from header import MiniDumpHeader

class MiniDumpContext:

    def __init__(self, dumpType):
        self.hdr = MiniDumpHeader()
        self.name = "MiniDumpContext"
        self.pos = 0
        self.hdr.Flags = dumpType

    # write a MINIDUMP_HEADER into section
    def write_header(self, fd, NumberOfStreams):
        self.hdr.NumberOfStreams = NumberOfStreams
        self.hdr.StreamDirectoryRva = len(self.hdr.to_bytes())
        fd.seek(0, os.SEEK_SET)
        fd.write(self.hdr.to_bytes())

        # Create data directory
        for x in range(NumberOfStreams):
            fd.write(struct.pack('<III', 0, 0, 0))

        fd.flush()
        #fd.seek(pos, os.SEEK_SET)
    
    def write_stream_info(self, fd, index, streamType, DataSize, RVA):
        pos = fd.tell()

        if self.hdr.StreamDirectoryRva == 0:
            raise Exception('write_stream_info must be called after write_header')

        if index >= self.hdr.NumberOfStreams:
            raise Exception('stream must be in 0..{}'.format(self.hdr.NumberOfStreams-1))

        # 4 byte for STREAM_TYPE 4 byte DataSize 4 byte RVA
        newpos = self.hdr.StreamDirectoryRva + (index * 12)
        fd.seek(newpos, os.SEEK_SET)
        fd.write(struct.pack('<III', streamType, DataSize, RVA))
        
        # reset ...
        fd.flush()
        fd.seek(pos, os.SEEK_SET)

    def append(self, fd, buffer, size):
        pos = fd.tell()

        # move on tail..
        fd.seek(0, os.SEEK_END)
        fd.write(buffer)
        
    def __str__(self):
        return self.name
