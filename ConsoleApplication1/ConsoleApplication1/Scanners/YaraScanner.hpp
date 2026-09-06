#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <functional>

namespace YaraScanner {

    enum class TargetType {
        PROCESS_MEMORY,
        FILE_DISK
    };

    enum class MatchPatternType {
        TEXT_ASCII,
        TEXT_WIDE,
        HEX_BYTES
    };

    struct YaraPattern {
        std::string Identifier;               // e.g. "$str1", "$hex1"
        MatchPatternType Type = MatchPatternType::TEXT_ASCII;
        std::string TextValue;                // for text patterns
        std::vector<BYTE> ByteSequence;       // for hex or converted text
        std::vector<bool> ByteMask;           // true = check, false = wildcard (??)
        bool NoCase = true;
        bool Wide = false;
        bool Ascii = true;
        bool FullWord = false;
    };

    enum class ConditionMode {
        ANY_OF_THEM,
        ALL_OF_THEM,
        AT_LEAST_N,
        EXPLICIT_ID
    };

    struct YaraRule {
        std::string Name;
        std::vector<std::string> Tags;
        std::map<std::string, std::string> Meta;
        std::vector<YaraPattern> Patterns;
        ConditionMode Condition = ConditionMode::ANY_OF_THEM;
        int RequiredMatches = 1;
        std::string Severity = "CRITICAL";   // "CRITICAL", "HIGH", "MEDIUM"
        std::string Description;
    };

    struct YaraDetection {
        std::string RuleName;
        std::string Severity;                // "CRITICAL", "HIGH", "MEDIUM"
        std::string Description;
        std::vector<std::string> Tags;
        std::vector<std::string> MatchedPatterns;
        TargetType Type = TargetType::PROCESS_MEMORY;
        std::string TargetIdentifier;        // Process Name (PID) or File Path
        DWORD ProcessId = 0;
        uint64_t MemoryAddressOrOffset = 0;
        float Confidence = 0.95f;
    };

    // Initialize engine & load embedded rules
    void Initialize();

    // Query number of active rules
    size_t GetLoadedRuleCount();

    // Load additional rules from a .yar / .yara file or directory
    size_t LoadRulesFromFile(const std::string& filePath);
    size_t LoadRulesFromDirectory(const std::string& directoryPath);
    bool LoadRuleFromString(const std::string& ruleSource);

    // Scan raw memory or file buffer
    std::vector<YaraDetection> ScanBuffer(const BYTE* data, size_t size, 
                                         const std::string& targetLabel, 
                                         TargetType type, 
                                         DWORD pid = 0, 
                                         uint64_t baseAddr = 0);

    // Scan a file on disk
    std::vector<YaraDetection> ScanFile(const std::string& filePath);

    // Scan memory regions of a target process
    std::vector<YaraDetection> ScanProcessMemory(DWORD pid, const std::string& processName);

    // Scan all active non-whitelisted processes
    std::vector<YaraDetection> ScanAllProcesses();

    // Scan high-risk disk drop folders (Temp, Downloads, Desktop, AppData)
    std::vector<YaraDetection> ScanDropLocations();

    // Complete YARA sweep pipeline (Processes + Drop locations)
    std::vector<YaraDetection> RunCompleteYaraSweep(DWORD targetPid = 0, const std::string& targetName = "");

} // namespace YaraScanner
