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
	std::cout << " Version " << pHeader->Version << std::endl;
	DUMP_HEX_SYMBOL(" Number of Streams ", pHeader->NumberOfStreams);
	DUMP_HEX_SYMBOL(" Stream Directory RVA ", pHeader->StreamDirectoryRva);
	std::cout << " Checksum " << std::hex << pHeader->CheckSum << std::endl;
	std::cout << " TimeDateStamp " << std::hex << pHeader->TimeDateStamp << std::endl;
	std::cout << " Flags " << std::hex << pHeader->Flags << std::hex;
}

void MiniDumpReader::parseStreamDirectory()
{
	std::cout << "---- MINIDUMP stream info " << std::endl;

	PMINIDUMP_DIRECTORY pDirectory = (PMINIDUMP_DIRECTORY)(buffer_ + pHeader->StreamDirectoryRva);

	for (int i = 0; i < pHeader->NumberOfStreams; i++, pDirectory++) {
		std::cout << " - Stream " << i + 1 << std::endl;

		std::cout << " - Type: " << std::hex << pDirectory->StreamType << std::endl;
		std::cout << " - RVA: " << std::hex << pDirectory->Location.Rva << std::endl;
		std::cout << " - Size: " << std::hex << pDirectory->Location.DataSize << std::endl;

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
}

void MiniDumpReader::unusedStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;
}


void MiniDumpReader::ceUnusedStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - CE Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;
}

void MiniDumpReader::threadListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - THREAD LIST Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

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
	std::cout << " - MODULE LIST Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

	PMINIDUMP_MODULE_LIST pModuleList = (PMINIDUMP_MODULE_LIST)(buffer_ + pMdDirectory->Location.Rva);

	std::cout << " - Number of Modules " << pModuleList->NumberOfModules << std::endl;

	PMINIDUMP_MODULE pModule = pModuleList->Modules;
	for (int i = 0; i < pModuleList->NumberOfModules; i++, pModule++) {
		std::wstring moduleName = getStringW(pModule->ModuleNameRva);

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
	std::cout << " - MEMORY LIST Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::exceptionListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - EXCEPTION LIST Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::systemInfoStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - SYSTEM INFO Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::threadExListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - THREADEX LIST Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::memory64ListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - MEMORY64 LIST Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::commentStreamA(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - COMMENTA Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::commentStreamW(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - COMMENTW Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::handleDataStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - HANDLE DATA Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::functionTableStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - FUNCTION TABLE Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::unloadedModuleListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - UNLOADED MODULE LIST Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::miscInfoStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - MISC INFO Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::threadInfoListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - THREAD INFO LIST Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::handleOperationListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - HANDLE OPERATION LIST Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::tokenStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - TOKEN Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}

void MiniDumpReader::memoryInfoListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory)
{
	std::cout << " - MEMORY INFO LIST Stream " << streamType << std::endl;

	std::cout << " - Type: " << std::hex << pMdDirectory->StreamType << std::endl;
	std::cout << " - RVA: " << std::hex << pMdDirectory->Location.Rva << std::endl;
	std::cout << " - Size: " << std::hex << pMdDirectory->Location.DataSize << std::endl;

}


std::string MiniDumpReader::getString(RVA rva)
{
	return std::string();
}

std::wstring MiniDumpReader::getStringW(RVA rva)
{
	std::wstring r;

	const size_t *length = (const size_t *)(buffer_ + rva);
	const wchar_t *data = (const wchar_t *)(buffer_ + rva + 4);

	for (size_t i = 0; i < *length; i++, data++) {
		r += *data;
	}

	return r;
}