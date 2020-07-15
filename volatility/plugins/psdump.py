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

    def render_text(self, outfd, data):
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for pid, task, pagedata in data:
            if self._config.PID is not None and pid !=  int(self._config.PID):
                outfd.write("*" * 72 + "\n")
                outfd.write("Skipping {0} [{1:6}]".format(task.ImageFileName, pid, str(pid)))
            else:
                prevaddr = 0
                outfd.write("*" * 72 + "\n")

                task_space = task.get_process_address_space()
                outfd.write("Writing {0} [{1:6}] to {2}.dmp\n".format(task.ImageFileName, pid, str(pid)))

                f = open(os.path.join(self._config.DUMP_DIR, str(pid) + ".dmp"), 'wb')
                if pagedata:
                	for p in pagedata:
                		"""Alignment to p[0]"""
                		outfd.write("Reading block {0:02x} size {1:02x}\n".format(p[0], p[1]))

                		if prevaddr < p[0]:
                		    size = p[0] - prevaddr
                		    outfd.write("Allocating {0:02x} for alignment\n".format(size))
                		    n = 0
                		    align = bytearray(0x1000)
                		    while n < size:
                		       f.write(align)
                		       n += 0x1000

                		data = task_space.read(p[0], p[1])
                		if data == None:
                			if self._config.verbose:
                				outfd.write("Memory Not Accessible: Virtual Address: 0x{0:x} Size: 0x{1:x}\n".format(p[0], p[1]))
                		else:
                			f.write(data)

                		prevaddr = p[0] + p[1]
                else:
                	outfd.write("Unable to read pages for task.\n")
                f.close()
