import struct

# MiniDumpStreamType used as 
class MiniDumpStreamType:
    UnusedStream = 0
    ReservedStream0 = 1
    ReservedStream1 = 2
    ThreadListStream = 3
    ModuleListStream = 4
    MemoryListStream = 5
    ExceptionStream = 6
    SystemInfoStream = 7
    ThreadExListStream = 8
    Memory64ListStream = 9
    CommentStreamA = 10
    CommentStreamW = 11
    HandleDataStream = 12
    FunctionTableStream = 13
    UnloadedModuleStream = 14
    MiscInfoStream = 15
    MemoryInfoListStream = 16
    ThreadInfoListStream = 17
    HandleOperationListStream = 18
    TokenStream = 19

    # ceStream undefined...
    ceStreamUnused = 0x8000

    LastReservedStream = 0xffff

    def __init__(self):
        self.value = MiniDumpStreamType.UnusuedStream

    # convert MiniDumpStreamType in serializable value for structure...
    def to_bytes(self):
        t = struct.pack('c', self.value)
        return t

    def __str__(self):
        t = 'MiniDumpStreamType %s' % (self.value)
        return t

class MiniDumpType:
    MiniDumpNormal                         = 0x00000000
    MiniDumpWithDataSegs                   = 0x00000001
    MiniDumpWithFullMemory                 = 0x00000002
    MiniDumpWithHandleData                 = 0x00000004
    MiniDumpFilterMemory                   = 0x00000008
    MiniDumpScanMemory                     = 0x00000010
    MiniDumpWithUnloadedModules            = 0x00000020
    MiniDumpWithIndirectlyReferencedMemory = 0x00000040
    MiniDumpFilterModulePaths              = 0x00000080
    MiniDumpWithProcessThreadData          = 0x00000100
    MiniDumpWithPrivateReadWriteMemory     = 0x00000200
    MiniDumpWithoutOptionalData            = 0x00000400
    MiniDumpWithFullMemoryInfo             = 0x00000800
    MiniDumpWithThreadInfo                 = 0x00001000
    MiniDumpWithCodeSegs                   = 0x00002000
    MiniDumpWithoutAuxiliaryState          = 0x00004000
    MiniDumpWithFullAuxiliaryState         = 0x00008000
    MiniDumpWithPrivateWriteCopyMemory     = 0x00010000
    MiniDumpIgnoreInaccessibleMemory       = 0x00020000
    MiniDumpWithTokenInformation           = 0x00040000
    MiniDumpWithModuleHeaders              = 0x00080000
    MiniDumpFilterTriage                   = 0x00100000
    MiniDumpValidTypeFlags                 = 0x001fffff
