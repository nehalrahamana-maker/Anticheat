#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace PowerShellClearedRunScanner {

    enum class PSFindingType {
        HISTORY_FILE_CLEARED,       // ConsoleHost_history.txt wiped/empty
        EVENT_LOG_CLEARED,          // Security 1102 / System 104 within 7 days
        SCRIPTBLOCK_LOG_CLEARED,    // PS Operational log cleared
        OBFUSCATED_COMMAND,         // EncodedCommand / IEX / base64 in event 4104
        SUSPICIOUS_PROFILE,         // $PROFILE modified recently with cheat strings
        SUSPICIOUS_HISTORY_ENTRY,   // Cheat-related command in history file
        HISTORY_FILE_MISSING,       // History file deleted (anti-forensic)
        RUN_RANDOMIZER_DETECTED,    // Short cryptic commands suggesting randomized launchers
    };

    struct PSDetection {
        PSFindingType  FindingType;
        std::string    FindingTypeName;
        std::string    Evidence;        // The raw evidence string
        std::string    FilePath;        // Source file/log path
        int            ConfidenceScore; // 0-100
        std::string    Severity;        // "CRITICAL", "HIGH", "MEDIUM"
        std::string    Description;
        FILETIME       EventTime = {};  // When it happened (if known)
    };

    // Full scan — checks history, event logs, profiles, obfuscated commands
    std::vector<PSDetection> ScanAll();

} // namespace PowerShellClearedRunScanner
