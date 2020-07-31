import os
import struct

from . import *

from memory import MemoryStream
from header import MiniDumpHeader
from constants import MiniDumpStreamType
from constants import MiniDumpType
from context import MiniDumpContext
from systeminfo import SystemInfo

class MiniDump:
    def __init__(self):
        self.name = "MiniDump"

    def __str__(self):
        return self.name

class StreamObject:
    def __init__(self, streamType, content):
        self.streamType = streamType
        self.content = content
    
    def getStreamType(self):
        return self.streamType
    
    def getContent(self):
        return self.content
    
### MiniDumpWriter => serializable object
class MiniDumpWriter:
    def __init__(self, mdType):
        self.name = "MiniDumpWriter"
        self.memory64 = []
        self.mdType = mdType
        self.streams = []

    def __str__(self):
        return self.name
    
    def add_memory_dump(self, va, size, buffer):
        m = MemoryStream(va, size, buffer)
        self.memory64.append(m)

    # number of streams available..
    def getNumberOfStreams(self):
        i = len(self.Streams)
        if len(self.memory64) > 0:
            i = i + 1
        else:
            # nothing!

        return i

    def add_stream(self, streamType, streamContent):
        stream = StreamObject(streamType, streamContent)

    # write data into buffer...
    def write(self, fd):
        ctx = MiniDumpContext(self.mdType)

        numberOfStreams = self.getNumberOfStreams()
        ctx.write_header(fd, numberOfStreams)

        currStream = 0

        # write content of streams...
        for stream in self.streams:
            ctx.add_stream_data(fd, currStream, stream.getStreamType(), stream.getContent())
            currStream = currStream + 1

        # append memory64 raw content at end of list..
        fd.flush()
        Memory64DataSize = 16 + len(self.memory64) * 16
        Memory64StreamOff = fd.tell()
        BaseRVA = fd.tell()
        BaseRVA = BaseRVA + 16  # two i64 for header
        BaseRVA = BaseRVA + (len(self.memory64) * 16) # and 16 bytes for each range..
        
        memoryList = struct.pack('<QQ', len(self.memory64), BaseRVA)
        fd.write(memoryList)
        
        # write datablock..
        for m in self.memory64:
            fd.write(struct.pack('<QQ', m.va, m.size))

        fd.flush()

        if len(self.memory64) > 0:
            ctx.write_stream_info(fd, currStream, MiniDumpStreamType.Memory64ListStream, Memory64DataSize, Memory64StreamOff)
            currStream = currStream + 1

        # write all memory64 stream into file...
        for m in self.memory64:
            ctx.append(fd, m.to_bytes(), m.length())

        # dump done...