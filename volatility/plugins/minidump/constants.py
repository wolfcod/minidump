import enum

# MiniDumpStreamType used as 
class MiniDumpStreamType(enum.IntEnum):
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
        t = int(self.value).to_bytes(1, byteorder = 'little', signed = false)

    def __str__(self):
        t = 'MiniDumpStreamType %s' % (self.value)
        return t
