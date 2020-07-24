import os

from . import memory
from . import descriptor
from . import header

from memory import MemoryStream
from header import MiniDumpHeader

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
        
    # write data into buffer...
    def write(self, fd):
        header = MiniDumpHeader()
        numberOfStreams = 0

        header.NumberOfStreams = len(self.memory)

        fd.write(header.to_bytes())

        memoryStream = []
        memory64Stream = []

        # write all memory stream into file...
        for m in self.memory:
            fd.flush()
            pos = fd.tell()
            fd.write(m.to_bytes())
            memoryStream.append(m.getDescriptor(pos))

        # write all memory64 stream into file...
        for m in self.memory64:
            fd.flush()
            pos = fd.tell()
            fd.write(m.to_bytes())
            memory64Stream.append(m.getDescriptor(pos))

        # build memory list stream
        # todo

        # build memory64 list stream
        # todo

        # build stream directory
        fd.flush()
        streamPosition = fd.tell()

        # update directory
        header.NumberOfStreams = numberOfStreams
        print ("Stream position ", streamPosition)
        header.StreamDirectoryRva = streamPosition
        
        fd.seek(0, os.SEEK_SET)
        fd.write(header.to_bytes())
