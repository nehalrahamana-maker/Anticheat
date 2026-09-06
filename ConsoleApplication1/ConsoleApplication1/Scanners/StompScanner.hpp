#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "PEParser.hpp"

namespace StompScanner {

    struct StompDetection {
        DWORD ProcessId;
        std::string ProcessName;
        std::string ModuleName;
        std::wstring ModulePath;
        ULONG_PTR ModuleBase;
        std::string SectionName;
        DWORD SectionRVA;
        DWORD SectionSize;
        std::string DiskHash;
        std::string MemoryHash;
        DWORD ModifiedBytesCount;
        DWORD FirstModifiedOffset;
        std::vector<BYTE> DiskSample;
        std::vector<BYTE> MemorySample;
        std::string MemoryProtection;
        std::string HeuristicType; // e.g. "TRAMPOLINE_JMP", "SHELLCODE_PAYLOAD", "SECTION_OVERWRITE", "RWX_ANOMALY"
        std::string Severity;      // "CRITICAL", "HIGH", "MEDIUM"
        std::string Description;
    };

    // Scan a specific process for module stomping and code section modifications
    std::vector<StompDetection> ScanProcess(DWORD pid, const std::string& procName);

    // Scan all active system processes
    std::vector<StompDetection> ScanAllProcesses();

    // Check specific known target modules commonly targeted for stomping
    bool IsCommonStompTarget(const std::string& moduleName);
}
