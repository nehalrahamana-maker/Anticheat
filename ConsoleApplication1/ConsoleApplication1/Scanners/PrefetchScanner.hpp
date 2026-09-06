#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace PrefetchScanner {

    struct PrefetchEntry {
        std::string  ExeName;           // e.g. "HDPLAYER.EXE"
        std::wstring PfFilePath;        // Full path to .pf file
        DWORD        RunCount   = 0;
        FILETIME     LastRun    = {};   // Most recent execution timestamp
        std::string  LastRunStr;
        bool         IsCheatMatch = false;
        std::string  MatchedKeyword;
        int          ConfidenceScore = 0;
        std::string  Severity;
        std::string  Description;
    };

    // Enumerate and parse C:\Windows\Prefetch\*.pf
    // Returns all entries; IsCheatMatch == true for flagged ones
    std::vector<PrefetchEntry> ScanPrefetch();

} // namespace PrefetchScanner
