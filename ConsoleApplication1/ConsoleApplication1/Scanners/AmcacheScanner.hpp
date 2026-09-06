#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace AmcacheScanner {

    struct AmcacheEntry {
        std::string  AppName;
        std::string  FilePath;
        std::string  SHA1Hash;
        std::string  FirstRunStr;
        FILETIME     FirstRun       = {};
        bool         IsCheatMatch   = false;
        std::string  MatchedKeyword;
        bool         IsKnownCheatHash = false; // matched against built-in hash table
        int          ConfidenceScore = 0;
        std::string  Severity;
        std::string  Description;
    };

    // Parse Amcache.hve and return all application entries
    // IsCheatMatch == true for flagged ones
    std::vector<AmcacheEntry> ScanAmcache();

} // namespace AmcacheScanner
