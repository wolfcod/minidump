import os
import struct

from . import *

from memory import MemoryStream
from header import MiniDumpHeader
from constants import MiniDumpStreamType
from constants import MiniDumpType
from context import MiniDumpContext

class MiniDump:
    def __init__(self):
        self.name = "MiniDump"

    def __str__(self):
        return self.name

### MiniDumpWriter => serializable object
class MiniDumpWriter:
    def __init__(self):
        self.name = "MiniDumpWriter"
        self.memory64 = []

    def __str__(self):
        return self.name
    
    def addMemory(self, va, size, buffer):
        m = MemoryStream(va, size, buffer)
        self.memory64.append(m)

    # number of streams available..
    def getNumberOfStreams(self):
        numberOfStreams = 0

        if len(self.memory64) > 0:
            numberOfStreams = numberOfStreams + 1
        
        return numberOfStreams

    # write data into buffer...
    def write(self, fd):
        ctx = MiniDumpContext(MiniDumpType.MiniDumpWithFullMemory)

        numberOfStreams = self.getNumberOfStreams()
        ctx.write_header(fd, numberOfStreams)

        # build memory list stream
        fd.flush()
        Memory64DataSize = 16 + len(self.memory64) * 16
        Memory64StreamOff = fd.tell()
        BaseRVA = fd.tell()
        BaseRVA = BaseRVA + 16  # two i64 for header
        BaseRVA = BaseRVA + (len(self.memory64) * 16) # and 16 bytes for each range..
        
        memoryList = struct.pack('<QQ', len(self.memory64), BaseRVA)
        fd.write(memoryList)
        
        currStream = 0
        # write datablock..
        for m in self.memory64:
            fd.write(struct.pack('<QQ', m.va, m.size))

        fd.flush()

        if len(self.memory64) > 0:
            ctx.write_stream_info(fd, currStream, MiniDumpStreamType.Memory64ListStream, Memory64DataSize, Memory64StreamOff)
            currStream = currStream + 1

        # write all memory64 stream into file...
        for m in self.memory64:
            ctx.append(fd, m.to_butes(), m.length())

        # build memory64 list stream
