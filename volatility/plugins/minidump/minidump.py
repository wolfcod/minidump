import os
import struct

from . import *

from memory import MemoryStream
from header import MiniDumpHeader
from constants import MiniDumpStreamType

class MiniDumpContext:
    def __init__(self, fd, dumpType):
        self.fd = fd
        self.hdr = MiniDumpHeader()
        self.name = "MiniDumpContext"
        self.pos = 0
        self.Flags = dumpType

    # write a MINIDUMP_HEADER into section
    def write_header(self, NumberOfStreams):
        pos = fd.tell()
        
        self.hdr.NumberOfStreams = NumberOfStreams
        self.hdr.StreamDirectoryRva = len(self.hdr.to_bytes())
        fd.seek(0, os.SEEK_SET)
        fd.write(hdr.to_bytes())

        # Create data directory
        for x in range(NumberOfStreams):
            fd.write(struct.pack('<III', 0, 0, 0))

        fd.flush()
        fd.seek(pos, os.SEEK_SET)
    
    def write_stream_info(self, index, streamType, DataSize, RVA):
        pos = fd.tell()

        if self.hdr.StreamDirectoryRva == 0:
            raise Exception('write_stream_info must be called after write_header')

        if index >= self.hdr.NumberOfStreams:
            raise Exception('stream must be in 0..{}'.format(self.hdr.NumberOfStreams-1))

        # 4 byte for STREAM_TYPE 4 byte DataSize 4 byte RVA

        newpos = self.hdr.StreamDirectoryRva + (index * 12)
        fd.seek(newpos, os.SEEK_SET)
        fd.write(stream.pack('<III', streamType, DataSize, RVA)
        
        # reset ...
        fd.flush()
        fd.seek(pos, os.SEEK_SET)

    def __str__(self):
        return self.name

class MiniDump:
    def __init__(self):
        self.name = "MiniDump"

    def __str__(self):
        return self.name

### MiniDumpWriter => serializable object
class MiniDumpWriter:
    def __init__(self):
        self.name = "MiniDumpWriter"
        self.memory = []
        self.memory64 = []

    def __str__(self):
        return self.name
    
    def addMemory(self, va, size, buffer):
        m = MemoryStream(va, size, buffer)
        self.memory.append(m)

    # number of streams available..
    def getNumberOfStreams(self):
        if len(self.memory) > 0:
            numberOfStreams = numberOfStreams + 1

        if len(self.memory64) > 0:
            numberOfStreams = numberOfStreams + 1
        
        return numberOfStreams

    # write data into buffer...
    def write(self, fd):
        ctx = MiniDumpContext(fd)

        numberOfStreams = self.getNumberOfStreams()
        ctx.write_header(numberOfStreams)
        currStream = 0

        memoryStream = []
        memory64Stream = []
        
        # write all memory stream into file...
        for m in self.memory:
            fd.flush()
            pos = fd.tell()
            fd.write(m.to_bytes())
            desc = m.getDescriptor(pos)

            print("Descriptor is ", desc)
            memoryStream.append(desc)

        # write all memory64 stream into file...
        #for m in self.memory64:
        #    fd.flush()
        #    pos = fd.tell()
        #    fd.write(m.to_bytes())
        #    memory64Stream.append(m.getDescriptor(pos))

        # build memory list stream
        fd.flush()
        memoryListRVA = fd.tell()
        memoryListSize = 0

        for m in memoryStream:
            print("t is ", m)
            fd.write(m.to_bytes())
            memoryListSize =  memoryListSize + 8

        fd.flush()

        if len(self.memory > 0):
            ctx.write_stream_info(currStream, MiniDumpStreamType.MemoryListStream, memoryListSize, memoryListRVA)
        
        # build memory64 list stream
