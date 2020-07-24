#include <Windows.h>
#include <iostream>

#include "minidump.h"

MiniDumpReader::MiniDumpReader(const char *buffer, size_t length)
	: buffer_(buffer), length_(length)
{
	pHeader = (PMINIDUMP_HEADER)buffer;
}

MiniDumpReader::~MiniDumpReader()
{
}

bool MiniDumpReader::hasValidSignature() const
{
	if (MINIDUMP_SIGNATURE != pHeader->Signature)
		return false;

	return true;
}

#define DUMP_HEX_SYMBOL(str, field) std::cout << str << std::hex << field << std::endl

void MiniDumpReader::dumpHeader()
{
	std::cout << "---- MINIDUMP header info " << std::endl;

	std::cout << " Signature " << ((hasValidSignature()) ? "valid." : "invalid.") << std::endl;
	DUMP_HEX_SYMBOL(" Version ", pHeader->Version);
	DUMP_HEX_SYMBOL(" Number of Streams ", pHeader->NumberOfStreams);
	DUMP_HEX_SYMBOL(" Stream Directory RVA ", pHeader->StreamDirectoryRva);
	DUMP_HEX_SYMBOL(" Checksum ", pHeader->CheckSum);
	DUMP_HEX_SYMBOL(" TimeDateStamp ", pHeader->TimeDateStamp);
	DUMP_HEX_SYMBOL(" Flags ", pHeader->Flags);
}

void MiniDumpReader::parseStreamDirectory()
{
	std::cout << "---- MINIDUMP stream info " << std::endl;

	PMINIDUMP_DIRECTORY pDirectory = (PMINIDUMP_DIRECTORY)(buffer_ + pHeader->StreamDirectoryRva);

	RVA maxRVA = 0;

	for (int i = 0; i < pHeader->NumberOfStreams; i++, pDirectory++) {
		std::cout << " - Stream " << i + 1 << std::endl;

		std::cout << " - Type: " << std::hex << pDirectory->StreamType << std::endl;
		std::cout << " - RVA: " << std::hex << pDirectory->Location.Rva << std::endl;
		std::cout << " - Size: " << std::hex << pDirectory->Location.DataSize << std::endl;

		if (pDirectory->Location.Rva + pDirectory->Location.DataSize > maxRVA)
			maxRVA = pDirectory->Location.Rva + pDirectory->Location.DataSize;

		switch (pDirectory->StreamType) {
		case UnusedStream: 
		case ReservedStream0: 
		case ReservedStream1: 
			unusedStream((MINIDUMP_STREAM_TYPE) pDirectory->StreamType, pDirectory);
			break;
		case ThreadListStream: threadListStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case ModuleListStream: moduleListStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case MemoryListStream: memoryListStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case ExceptionStream: exceptionListStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case SystemInfoStream: systemInfoStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case ThreadExListStream: threadExListStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case Memory64ListStream: memory64ListStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case CommentStreamA: commentStreamA((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case CommentStreamW: commentStreamW((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case HandleDataStream: handleDataStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case FunctionTableStream: functionTableStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case UnloadedModuleListStream: unloadedModuleListStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case MiscInfoStream: miscInfoStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case MemoryInfoListStream: memoryInfoListStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case ThreadInfoListStream: threadInfoListStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case HandleOperationListStream: handleOperationListStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;
		case TokenStream: tokenStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory); break;;
		
		case ceStreamNull:
		case ceStreamSystemInfo:
		case ceStreamException:
		case ceStreamModuleList:
		case ceStreamProcessList:
		case ceStreamThreadList:
		case ceStreamThreadContextList:
		case ceStreamThreadCallStackList:
		case ceStreamMemoryVirtualList:
		case ceStreamMemoryPhysicalList:
		case ceStreamBucketParameters:
		case ceStreamProcessModuleMap:
		case ceStreamDiagnosisList:
			ceUnusedStream((MINIDUMP_STREAM_TYPE)pDirectory->StreamType, pDirectory);
			break;

		case LastReservedStream: break;

		}
	}

	std::cout << "Max RVA indexed => " << std::hex << maxRVA << std::endl;
}

void MiniDumpReader::dumpDirectoryData(const std::string &type, MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - " << type.c_str() << " " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;
}

void MiniDumpReader::unusedStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("Stream", streamType, pMdDirectory);
}


void MiniDumpReader::ceUnusedStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("CE Stream", streamType, pMdDirectory);
}

void MiniDumpReader::threadListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("THREAD LIST Stream", streamType, pMdDirectory);

	PMINIDUMP_THREAD_LIST pThreadList = (PMINIDUMP_THREAD_LIST)(buffer_ + pMdDirectory->Location.Rva);

	std::cout << " - Number of Thread " << pThreadList->NumberOfThreads << std::endl;
	
	PMINIDUMP_THREAD pThread = pThreadList->Threads;
	for (int i = 0; i < pThreadList->NumberOfThreads; i++, pThread++) {
		std::cout << " - - Thread Id " << pThread->ThreadId << std::endl;
		std::cout << " - - Suspend Count " << pThread->SuspendCount << std::endl;
		std::cout << " - - Priority Class " << pThread->PriorityClass << std::endl;
		std::cout << " - - Priority " << pThread->Priority << std::endl;
		std::cout << " - - Teb " << pThread->Teb << std::endl;

		std::cout << " - - STACK: " << std::endl;
		std::cout << " Address: " << std::hex << pThread->Stack.StartOfMemoryRange << std::endl;
		std::cout << " Size:" << std::hex << pThread->Stack.Memory.DataSize << std::endl;
		
		std::cout << " - - CONTEXT: " << std::endl;
		std::cout << " Address: " << std::hex << pThread->ThreadContext.Rva << std::endl;
		std::cout << " Size:" << std::hex << pThread->ThreadContext.DataSize << std::endl;

		CONTEXT c = { 0 };

		memcpy(&c, pThread->ThreadContext.Rva + buffer_, pThread->ThreadContext.DataSize);

		std::cout << "Register EAX => " << std::hex << c.Eax << std::endl;
	}
}

void MiniDumpReader::moduleListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("MODULE LIST Stream", streamType, pMdDirectory);

	PMINIDUMP_MODULE_LIST pModuleList = (PMINIDUMP_MODULE_LIST)(buffer_ + pMdDirectory->Location.Rva);

	std::cout << " - Number of Modules " << pModuleList->NumberOfModules << std::endl;

	PMINIDUMP_MODULE pModule = pModuleList->Modules;
	for (int i = 0; i < pModuleList->NumberOfModules; i++, pModule++) {
		std::wstring moduleName = getData<std::wstring, wchar_t>(pModule->ModuleNameRva);

		std::wcout << " - - " << moduleName.c_str() << std::endl;

		std::cout << " - - BaseOfImage " << pModule->BaseOfImage << std::endl;
		std::cout << " - - SizeOfImage " << pModule->SizeOfImage << std::endl;
		std::cout << " - - CheckSum " << pModule->CheckSum << std::endl;
		std::cout << " - - TimeDateStamp " << pModule->TimeDateStamp << std::endl;
		std::cout << " - - ModlpszModuleNameuleNameRva " << pModule->ModuleNameRva << std::endl;

	}

}

void MiniDumpReader::memoryListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("MEMORY LIST Stream", streamType, pMdDirectory);

	PMINIDUMP_MEMORY_LIST pMemoryList = (PMINIDUMP_MEMORY_LIST)(buffer_ + pMdDirectory->Location.Rva);

	std::cout << " - Number of Modules " << pMemoryList->NumberOfMemoryRanges << std::endl;

	MINIDUMP_MEMORY_DESCRIPTOR *pMemoryRange = pMemoryList->MemoryRanges;

	for (int i = 0; i < pMemoryList->NumberOfMemoryRanges; i++, pMemoryRange++) {
		std::cout << " From " << pMemoryRange->StartOfMemoryRange << " " << pMemoryRange->Memory.DataSize << " " << " at " << pMemoryRange->Memory.Rva << std::endl;
	}

}

void MiniDumpReader::exceptionListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("EXCEPTION LIST Stream", streamType, pMdDirectory);
}

void MiniDumpReader::systemInfoStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("SYSTEMINFO Stream", streamType, pMdDirectory);
}

void MiniDumpReader::threadExListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("THREADEX LIST Stream", streamType, pMdDirectory);
}

void MiniDumpReader::memory64ListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("MEMORY64 LIST Stream", streamType, pMdDirectory);
}

void MiniDumpReader::commentStreamA(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("COMMENTA Stream", streamType, pMdDirectory);
}

void MiniDumpReader::commentStreamW(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("COMMENTW Stream", streamType, pMdDirectory);
}

void MiniDumpReader::handleDataStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("HANDLE DATA Stream", streamType, pMdDirectory);
}

void MiniDumpReader::functionTableStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("FUNCTION TABLE Stream", streamType, pMdDirectory);
}

void MiniDumpReader::unloadedModuleListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("UNLOADED MODULE LIST Stream", streamType, pMdDirectory);
}

void MiniDumpReader::miscInfoStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("MISC INFO Stream", streamType, pMdDirectory);
}

void MiniDumpReader::threadInfoListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("THREAD INFO LIST Stream", streamType, pMdDirectory);
}

void MiniDumpReader::handleOperationListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("HANDLE OPERATION LIST Stream", streamType, pMdDirectory);
}

void MiniDumpReader::tokenStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("TOKEN Stream", streamType, pMdDirectory);
}

void MiniDumpReader::memoryInfoListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	dumpDirectoryData("MEMORY INFO LIST Stream", streamType, pMdDirectory);

	PMINIDUMP_MEMORY_INFO_LIST pMemoryList = (PMINIDUMP_MEMORY_INFO_LIST)(buffer_ + pMdDirectory->Location.Rva);

	std::cout << " - Number of Entries " << pMemoryList->NumberOfEntries << std::endl;
	std::cout << " - Size of Entry " << pMemoryList->SizeOfEntry << " == " << sizeof(MINIDUMP_MEMORY_INFO) << std::endl;
	std::cout << " - Size of Header " << pMemoryList->SizeOfHeader << std::endl;	

	MINIDUMP_MEMORY_INFO *memoryInfo = (MINIDUMP_MEMORY_INFO *)(buffer_ + pMdDirectory->Location.Rva + pMemoryList->SizeOfHeader);
	
	SIZE_T allocated = 0;

	for (int i = 0; i < pMemoryList->NumberOfEntries; i++, memoryInfo++) {
		std::cout << " -- BaseAddress " << std::hex << memoryInfo->BaseAddress << std::endl;
		std::cout << " -- AllocationBase " << std::hex << memoryInfo->AllocationBase << std::endl;
		if (memoryInfo->AllocationProtect != 0)
			allocated += memoryInfo->RegionSize;

		std::cout << " -- AllocationProtect " << std::hex << memoryInfo->AllocationProtect << std::endl;
		std::cout << " -- RegionSize " << std::hex << memoryInfo->RegionSize << std::endl;
	};

	std::cout << "Allocated memory available ? =" << std::hex << allocated << std::endl;
}
