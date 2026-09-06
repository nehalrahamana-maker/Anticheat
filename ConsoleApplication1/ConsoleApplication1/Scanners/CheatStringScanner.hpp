#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace CheatStringScanner {

    // How the string was found
    enum class ScanSource {
        PROCESS_MEMORY,   // Found in a running process's memory
        DISK_EXECUTABLE,  // Found in a file on disk (HDD player / dropped exe)
    };

    struct CheatStringDetection {
        ScanSource   Source        = ScanSource::PROCESS_MEMORY;

        // Process-memory fields
        DWORD        ProcessId     = 0;
        std::string  ProcessName;

        // Disk-file fields
        std::wstring FilePath;

        // Detection info
        std::string  MatchedString;          // The keyword that triggered the hit
        std::string  ContextSnippet;         // Up to 128 printable chars surrounding the hit
        std::string  Category;               // e.g. "AIMBOT", "SPOOFER", "BYPASS", etc.
        std::string  Severity;               // "CRITICAL", "HIGH", "MEDIUM"
        int          ConfidenceScore  = 0;   // 0-100 multi-factor confidence
        std::string  VerificationDetail;     // Human-readable verification evidence
        std::string  Description;
    };

    // Scan all running processes for plaintext cheat strings in memory
    std::vector<CheatStringDetection> ScanAllProcesses();

    // Scan a specific process for plaintext cheat strings in memory
    std::vector<CheatStringDetection> ScanProcess(DWORD pid, const std::string& procName);

    // Scan on-disk executables in common locations (Desktop, Temp, Downloads, AppData)
    // for HDD-player / dropped cheat exes
    std::vector<CheatStringDetection> ScanDiskExecutables();

} // namespace CheatStringScanner
