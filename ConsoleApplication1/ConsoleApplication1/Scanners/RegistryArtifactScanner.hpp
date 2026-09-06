#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace RegistryArtifactScanner {

    struct RegArtifactDetection {
        std::string KeyPath;
        std::string ValueName;
        std::string ArtifactType; // BAM_EXECUTION_LOG, MUICACHE_EXECUTION_RECORD, COMPAT_ASSISTANT_STORE, USERASSIST_RECORD
        std::string Severity;     // CRITICAL, HIGH
        std::string Description;
    };

    // Deep registry audit for historical execution traces of deleted or unloaded cheats
    std::vector<RegArtifactDetection> ScanRegistryArtifacts();
}
