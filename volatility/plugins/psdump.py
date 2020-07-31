# Volatility
#
# psdump - Create a flat file with all data available for a process

# Author:
# cod <cod@sysleave.org>
#


"""psdump example file"""

import os
import struct
from volatility import renderers
from volatility.commands import Command
import volatility.plugins.taskmods as taskmods
import volatility.debug as debug
import volatility.obj as obj
import volatility.exceptions as exceptions
from volatility.renderers.basic import Address
import minidump
from minidump import MiniDumpWriter
from minidump import SystemInfo
from minidump import MiniDumpStreamType
from minidump import MiniDumpType
from minidump import MemoryInfoListStream

class PsDump(taskmods.MemDump):
    """Dump memory process to an dmp file"""
    def __init__(self, config, *args, **kwargs):
        taskmods.MemMap.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump executable files')
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')
        config.add_option('ADDR', short_option = 'a', default = None,
                          help = 'Show info on VAD at or containing this address',
                          action = 'store', type = 'int')
        config.add_option('ÚSERMODE', short_option = 'u',
                          help = 'Dump pages only from userland range..',
                          action = 'store_true', default=True)
              
    def create_sysinfo(self, task):
        sysinfo = SystemInfo()

        # collecting sysinfo for this task
        sysinfo.MajorVersion = task.Peb.OSMajorVersion
        sysinfo.MinorVersion = task.Peb.OSMinorVersion
        sysinfo.BuildNumber = task.Peb.OSBuildNumber
        sysinfo.PlatformId = task.Peb.OSPlatformId
        #sysinfo.CSDVersion = task.Peb.CSDVersion
        sysinfo.CSDVersion = "volatility PsDump".encode('utf-16')

        return sysinfo

    def createMemoryList(self, outfd, task):
        memoryList = MemoryInfoListStream()

        for vad in task.VadRoot.traverse():
            if (self._config.ADDR is not None and 
                (self._config.ADDR < vad.Start or 
                self._config.ADDR > vad.End)):
                continue
            if vad == None:
                outfd.write("Error: {0}".format(vad))
            else:
                memoryList.add_va(vad.Start, vad.Start, vad.VadFlags.Protection.v(), vad.End - vad.Start,
                                  vad.VadFlags.VadType.v(), vad.VadFlags.Protection.v(), 0x20000)
        return memoryList

    def render_text(self, outfd, data):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for pid, task, pagedata in data:

            mdw = MiniDumpWriter(MiniDumpType.MiniDumpWithFullMemory)
            f = open(os.path.join(self._config.DUMP_DIR, str(pid) + ".dmp"), 'wb')

            if self._config.PID is not None and pid !=  int(self._config.PID):
                outfd.write("*" * 72 + "\n")
                outfd.write("Skipping {0} [{1:6}]".format(task.ImageFileName, pid, str(pid)))
            else:
                outfd.write("*" * 72 + "\n")
                outfd.write("Getting Peb32 => {0}\n".format(task.Peb.OSMajorVersion))
                task_space = task.get_process_address_space()
                outfd.write("Writing {0} [{1:6}] to {2}.dmp\n".format(task.ImageFileName, pid, str(pid)))
                
                # create SysInfo stream from task..
                sysinfo = self.create_sysinfo(task)

                mdw.add_stream(MiniDumpStreamType.SystemInfoStream, sysinfo.to_bytes())

                if pagedata:
                    for p in pagedata:
                        """Alignment to p[0]"""
                        outfd.write("Reading block {0:02x} size {1:02x}\n".format(p[0], p[1]))

                        data = task_space.read(p[0], p[1])
                        if data == None:
                            if self._config.verbose:
                                outfd.write("Memory Not Accessible: Virtual Address: 0x{0:x} Size: 0x{1:x}\n".format(p[0], p[1]))
                        else:
                            mdw.add_memory_dump(p[0], p[1], data)

                        prevaddr = p[0] + p[1]
                else:
                    outfd.write("Unable to read pages for task.\n")

            # write ThreadListStream
            # write ModuleListStream
            # write MemoryListStream

            # write MemoryListInfoStream
            memoryList = self.createMemoryList(outfd, task)
            mdw.add_stream(MiniDumpStreamType.MemoryInfoListStream, memoryList.to_bytes())

            # build crashdump file and append at end of file all dumped blocks... 

            f.close()

    def write_vad_short(self, outfd, vad):
        """Renders a text version of a Short Vad"""
        self.table_header(None,
                          [("VAD node @", str(len("VAD node @"))),
                           ("address", "[addrpad]"),
                           ("Start", "5"),
                           ("startaddr", "[addrpad]"),
                           ("End", "3"),
                           ("endaddr", "[addrpad]"),
                           ("Tag", "3"),
                           ("tagval", ""),
                           ])
        self.table_row(outfd, "VAD node @",
                              vad.obj_offset,
                              "Start",
                              vad.Start,
                              "End",
                              vad.End,
                              "Tag",
                              vad.Tag)
