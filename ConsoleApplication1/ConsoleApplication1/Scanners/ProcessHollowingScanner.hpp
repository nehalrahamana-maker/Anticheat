#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace ProcessHollowingScanner {

    struct ProcessHollowingDetection {
        DWORD ProcessId = 0;
        std::string ProcessName;
        ULONG_PTR ImageBaseAddress = 0;
        ULONG_PTR EntryPointInMemory = 0;
        ULONG_PTR EntryPointOnDisk = 0;
        std::string HollowingTechnique; // "PROCESS_HOLLOWING_ENTRYPOINT_MISMATCH", "PROCESS_DOPPELGANGING_MEM_PRIVATE_IMAGE", "PROCESS_GHOSTING_PATH_MISMATCH", "PE_HEADER_OVERWRITE_DETECTED"
        std::wstring ExpectedDiskPath;
        std::wstring MappedMemoryPath;
        std::string Severity;          // "CRITICAL", "HIGH"
        std::string Description;
    };

    // Scan a specific process for Process Hollowing, Doppelganging, Ghosting, and PE Header Replacement
    std::vector<ProcessHollowingDetection> ScanProcessHollowing(DWORD pid, const std::string& procName);

    // Scan all active processes for process hollowing / doppelganging attacks
    std::vector<ProcessHollowingDetection> ScanAllProcessesHollowing();

} // namespace ProcessHollowingScanner
