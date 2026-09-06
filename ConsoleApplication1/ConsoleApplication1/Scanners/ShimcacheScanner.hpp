#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace ShimcacheScanner {

    struct ShimcacheEntry {
        std::wstring FilePath;
        std::string  FilePathNarrow;
        FILETIME     LastModified   = {};
        std::string  LastModifiedStr;
        bool         IsCheatMatch   = false;
        std::string  MatchedKeyword;
        int          ConfidenceScore = 0;
        std::string  Severity;
        std::string  Description;
    };

    // Parse AppCompatCache (Shimcache) from registry
    // Returns all entries; IsCheatMatch == true for flagged ones
    std::vector<ShimcacheEntry> ScanShimcache();

} // namespace ShimcacheScanner
