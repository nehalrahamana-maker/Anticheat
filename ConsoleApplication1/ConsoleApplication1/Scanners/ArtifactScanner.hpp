#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace ArtifactScanner {

    struct FileArtifactDetection {
        std::string FilePath;
        std::string FileName;
        std::string ArtifactType; // PREFETCH_EXECUTION, APPDATA_CHEAT_BINARY, TEMP_PAYLOAD, SUSPICIOUS_LOG
        std::string Severity;     // CRITICAL, HIGH, MEDIUM
        std::string LastModified;
        uint64_t FileSizeBytes = 0;
        std::string Description;
    };

    // Deep scan for on-disk cheat artifacts, loader configs, and Windows Prefetch execution evidence
    std::vector<FileArtifactDetection> ScanFileSystemArtifacts();
}
