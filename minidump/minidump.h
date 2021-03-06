#pragma once

#include <DbgHelp.h>

class MiniDumpReader
{
	public:
		MiniDumpReader(const char *buffer, size_t length);
		
		~MiniDumpReader();

		bool hasValidSignature() const;

		void dumpHeader();
		void parseStreamDirectory();

	protected:
		void unusedStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void threadListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void moduleListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void memoryListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void exceptionListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void systemInfoStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void threadExListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void memory64ListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void commentStreamA(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void commentStreamW(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void handleDataStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void functionTableStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void unloadedModuleListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void miscInfoStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void threadInfoListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void handleOperationListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void tokenStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);
		void memoryInfoListStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);

		void ceUnusedStream(MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);

	private:
		void dumpDirectoryData(const std::string &type, MINIDUMP_STREAM_TYPE streamType, PMINIDUMP_DIRECTORY pMdDirectory);

	private:	/** internal data ... */
		const char *buffer_;
		const size_t length_;
		
		PMINIDUMP_HEADER pHeader;

private:
	/** template to extract a string in ascii or unicode from RVA*/
	template<typename R, typename T>
	R getData(RVA rva)
	{
		R r;

		const size_t *length = (const size_t *)(buffer_ + rva);
		const T *data = (const T *)(buffer_ + rva + 4);

		for (size_t i = 0; i < *length; i++, data++)
			r += *data;

		return r;
	}
};
