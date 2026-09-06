#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace AntiTamper {

    struct AntiTamperStatus {
        bool IsDebuggerAttached = false;
        bool HasHardwareBreakpoints = false;
        bool IsMemoryHooked = false;
        bool IsSelfCodeTampered = false;
        bool HasInjectedMemory = false;
        bool IsTampered = false;
        std::string ScannerImageSHA256;
        std::vector<std::string> TamperFlags;
        std::string StatusSummary;
    };

    // Performs complete self-protection, code section hash audit, and anti-injection scan on the scanner itself
    AntiTamperStatus AuditSelfIntegrity();
}
