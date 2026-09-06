#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace ETWScanner {

    struct ETWDetection {
        DWORD ProcessId = 0;
        std::string ProcessName;
        std::string TargetFunction;     // e.g. "ntdll.dll!EtwEventWrite", "wevtsvc.dll!EventLogWorkerThread"
        ULONG_PTR FunctionAddress = 0;
        std::string TamperTechnique;   // "ETW_PROLOGUE_PATCH_RET", "ETW_PROLOGUE_PATCH_XOR_EAX", "EVENTLOG_SERVICE_THREAD_SUSPENDED", "EVENTLOG_WEVTSVC_HOOKED"
        std::vector<BYTE> CleanDiskBytes;
        std::vector<BYTE> TamperedMemoryBytes;
        std::string Severity;          // "CRITICAL", "HIGH"
        std::string Description;
    };

    // Scan a specific process for ETW user-mode suppression patches (EtwEventWrite, EtwpEventWriteFull, NtTraceEvent)
    std::vector<ETWDetection> ScanProcessETWIntegrity(DWORD pid, const std::string& procName);

    // Scan the Windows EventLog svchost service for thread suspension (Phant0m / Event-Log-Cleaner attack) and wevtsvc.dll patches
    std::vector<ETWDetection> ScanEventLogServiceTampering();

    // Scan all active processes for ETW tampering + EventLog service audit
    std::vector<ETWDetection> ScanAllProcessesETW();

} // namespace ETWScanner
