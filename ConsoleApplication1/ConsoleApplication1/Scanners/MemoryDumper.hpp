#pragma once
#include <windows.h>
#include <string>

namespace MemoryDumper {

    struct DumpResult {
        bool Success = false;
        std::string SavedFilePath;
        SIZE_T BytesDumped = 0;
        std::string ErrorMessage;
    };

    // Dumps raw suspicious memory pages to disk for reverse-engineering in IDA Pro / Ghidra
    DumpResult DumpMemoryRegion(DWORD pid, ULONG_PTR baseAddress, SIZE_T sizeBytes, const std::string& outputFile);
}
