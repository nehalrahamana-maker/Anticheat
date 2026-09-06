#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace ThreadInspector {

    struct ThreadDetection {
        DWORD ProcessId = 0;
        std::string ProcessName;
        DWORD ThreadId = 0;
        ULONG_PTR StartAddress = 0;
        ULONG_PTR CurrentRip = 0;
        std::string DetectionType; // HARDWARE_BREAKPOINT_HOOK, GHOST_THREAD_UNBACKED_RIP, ETW_SUPPRESSION
        std::string Severity;      // CRITICAL, HIGH
        std::string Description;
    };

    // Deep inspection of all process threads
    std::vector<ThreadDetection> InspectProcessThreads(DWORD pid, const std::string& procName);
}
