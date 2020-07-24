#include <Windows.h>
#include <iostream>
#include <fstream>
#include <iterator>
#include "minidump.h"
#include "tclap/CmdLine.h"

using namespace TCLAP;

/** read file into vector... */
bool readFileContent(const std::string &fileName, std::vector<char> &buffer, size_t &length)
{
#ifdef _WIN32
	HANDLE hFile = CreateFileA(fileName.c_str(), FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	BY_HANDLE_FILE_INFORMATION info;

	GetFileInformationByHandle(hFile, &info);

	length = info.nFileSizeLow;
#else
	std::ifstream inFile(fileName, std::ios_base::binary);
	inFile.seekg(0, std::ios_base::end);
	length = inFile.tellg();
	inFile.seekg(0, std::ios_base::beg);
#endif
	if (length == 0)
		return false;

	buffer.reserve(length);
#ifdef _WIN32
	DWORD ignore = 0;
	ReadFile(hFile, buffer.data(), length, &ignore, NULL);
	CloseHandle(hFile);
#else
	std::copy(std::istreambuf_iterator<char>(inFile),
		std::istreambuf_iterator<char>(),
		std::back_inserter(buffer));

	inFile.close();
#endif
	return true;

}
int main(int argc, char **argv)
{
	CmdLine cmd("minidump reader", ' ', "1.0");

	ValueArg<std::string> fileNameArg("f", "file", "Minidump file name", true, "", "string");

	cmd.add(fileNameArg);

	try {
		cmd.parse(argc, argv);
	}
	catch (ArgException &e) {
		std::cout << "Exception " << e.error() << " argument " << e.argId() << std::endl;
		return 0;
	}

	std::vector<char> buffer;
	size_t length = 0;

	if (readFileContent(fileNameArg.getValue(), buffer, length) == false) {
		std::cout << "Error reading " << fileNameArg.getValue() << std::endl;
		return 0;
	}


	MiniDumpReader r(buffer.data(), length);

	if (!r.hasValidSignature()) {
		std::cout << "Error: Invalid signature into file." << std::endl;
	}


	r.dumpHeader();	// show a summary of header..
	r.parseStreamDirectory();

	return 0;
}