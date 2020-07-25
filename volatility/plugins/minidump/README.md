# minidump python library

This code is written following DbgHelp header file in Windows SDK

To speed up the development of code I used as reference the project [minidump](https://github.com/skelsec/minidump/) by skelsec user on GitHub.

## Debug from cmd
c:\Python27\python.exe vol.py --plugins=c:\git\minidump\volatility\plugins -f c:\temp\memdump.bin psdump --dump-dir=c:\temp\dump -p 1796