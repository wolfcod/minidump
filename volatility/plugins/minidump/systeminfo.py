import struct

class SystemInfo:
    def __init__(self):
        self.name = "SystemInfoS"
       
        #MINIDUMP_SYSTEM_INFO
        self.ProcessorArchitecture = 0
        self.ProcessorLevel = 0
        self.ProcessorRevision = 0

        self.NumberOfProcessors = 0
        self.ProductType = 0

        self.MajorVersion = 0
        self.MinorVersion = 0
        self.BuildNumber = 0
        self.PlatformId = 0

        self.CSDVersionRva = 0

        self.SuiteMask = 0
        self.Reserved2 = 0

#CPU Structure info
        self.VendorId0 = 0
        self.VendorId1 = 0
        self.VendorId2 = 0

        self.VersionInformation = 0
        self.FeatureInformation = 0
        self.AMDExtendedCpuFeature = 0

        self.ProcessorFeatures0 = 0
        self.ProcessorFeatures1 = 0

        self.CSDVersion = None

    def __name__(self):
        return self.__name__

    def getNumberOfStreams(self):
        return self.NumberOfStreams

    def to_bytes(self):
        t = struct.pack("<HHH", self.ProcessorArchitecture, self.ProcessorLevel, self.ProcessorRevision)

        t = struct.pack("BB", self.NumberOfProcessors, self.ProductType)
        
        t += struct.pack("<I", self.MajorVersion)
        t += struct.pack("<I", self.MinorVersion)
        t += struct.pack("<I", self.BuildNumber)
        t += struct.pack("<I", self.PlatformId)

        if self.CSDVersion is None:
            t += struct.pack("<I", 0)
        else:
            t += struct.pack("<I", 72)

        t += struct.pack("<HH", self.SuiteMask, self.Reserved2)

        t += struct.pack("<III", self.VendorId0, self.VendorId1, self.VendorId2)

        t += struct.pack("<I", self.VersionInformation)
        t += struct.pack("<I", self.FeatureInformation)
        t += struct.pack("<I", self.AMDExtendedCpuFeature)
        t += struct.pack("<QQ", self.ProcessorFeatures0, self.ProcessorFeatures1) # CPUInfo.ProcessorFeatures

        if self.CSDVersion is not None:
            t += self.CSDVersion
            
        return t

    def __str__(self):
        return "MiniDumpHeader object"
 
    