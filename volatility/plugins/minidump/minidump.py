import os

from minidump import *

class MiniDump:
    def __init__(self):
        self.name = "MiniDump"

    def __str__(self):
        return self.name

### MiniDumpWriter => serializable object
class MiniDumpWriter:
    def __init__(self):
        self.name = "MiniDumpWriter""
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

        header.NumberOfStreams = self.memory.count

        fd.write(header.to_bytes())

        memoryStream = []
        memory64Stream = []

        # write all memory stream into file...
        for m in self.memory:
            pos = os.lseek(fd, 0, os.SEEK_CUR)
            fd.write(m.to_bytes())
            memoryStream.append(m.getDescriptor(pos))

        # write all memory64 stream into file...
        for m in self.memory64:
            pos = os.lseek(fd, 0, os.SEEK_CUR)
            fd.write(m.to_bytes())
            memory64Stream.append(m.getDescriptor(pos))

        # build memory list stream
        # todo

        # build memory64 list stream
        # todo

        # build stream directory
        streamPosition = 0

        # update directory
        os.lseek(fd, 0, os.SEEK_SET)
        header.NumberOfStreams = numberOfStreams
        header.StreamDirectoryRva = streamPosition
        
        fd.write(header.to_butes())
