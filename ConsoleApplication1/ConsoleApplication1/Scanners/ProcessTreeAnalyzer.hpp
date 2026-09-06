#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace ProcessTreeAnalyzer {

    struct ProcessTreeDetection {
        DWORD ProcessId = 0;
        DWORD ParentProcessId = 0;
        std::string ProcessName;
        std::string ParentProcessName;
        std::string DetectionType; // PPID_SPOOFING, SUSPICIOUS_LOADER_PARENT, HIDDEN_ORPHAN_PROCESS
        std::string Severity;      // CRITICAL, HIGH
        std::string Description;
    };

    // Analyzes parent-child relationships and detects loader injection hierarchies
    std::vector<ProcessTreeDetection> AnalyzeProcessTrees();
}
