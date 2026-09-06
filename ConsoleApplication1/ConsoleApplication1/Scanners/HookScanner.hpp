#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace HookScanner {

    struct HookDetection {
        DWORD ProcessId;
        std::string ProcessName;
        std::string TargetFunction; // e.g. "ntdll.dll!NtOpenKey"
        ULONG_PTR FunctionAddress;
        ULONG_PTR HookDestination;
        std::string DestinationModule; // e.g. "clb.dll" or "Unbacked Memory"
        std::string HookType;          // "INLINE_DETOUR_JMP32", "INLINE_DETOUR_JMP64", "IAT_HOOK", "EAT_HOOK"
        std::vector<BYTE> CleanDiskBytes;
        std::vector<BYTE> HookedMemoryBytes;
        std::string Severity;          // "CRITICAL", "HIGH"
        std::string Description;
    };

    struct ClbDllDetection {
        std::wstring FilePath;
        bool Exists;
        bool IsMicrosoftSigned;
        std::string SignerSubject;
        std::string SHA256;
        bool IsRogueHookDll;
        std::string Severity;
        std::string Description;
    };

    // Scan for clb.dll on disk in System32 / SysWOW64
    std::vector<ClbDllDetection> ScanSystemClbDll();

    // Scan NTDLL and Kernel32 export prologues for Detours / inline hooks
    std::vector<HookDetection> ScanApiHooks(DWORD pid, const std::string& procName);

    // Scan all processes for clb.dll loaded modules and registry API hooks
    std::vector<HookDetection> ScanAllProcessHooks();
}
