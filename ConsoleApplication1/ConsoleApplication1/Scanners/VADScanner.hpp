#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace VADScanner {

    struct VADDetection {
        DWORD ProcessId = 0;
        std::string ProcessName;
        ULONG_PTR BaseAddress = 0;
        SIZE_T RegionSize = 0;
        std::string MemoryType;       // MEM_PRIVATE, MEM_MAPPED
        std::string MemoryProtection; // PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, etc.
        std::string DetectionType;   // PEB_UNLINKED_DLL, MANUAL_MAPPED_PE, UNBACKED_EXECUTABLE_SHELLCODE, RWX_ANOMALY
        std::string Severity;        // CRITICAL, HIGH
        std::vector<BYTE> MemorySample;
        std::string Description;
    };

    // Deep walk of process memory space to find floating/unbacked code pages and unlinked DLLs
    std::vector<VADDetection> ScanProcessVAD(DWORD pid, const std::string& procName);
}
