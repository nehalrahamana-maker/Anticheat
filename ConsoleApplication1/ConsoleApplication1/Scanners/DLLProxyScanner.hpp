#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace DLLProxyScanner {

    // Describes a single suspicious DLL loaded into a process
    struct DLLProxyDetection {
        DWORD       ProcessId = 0;
        std::string ProcessName;

        // The path of the loaded DLL as reported by the process module list
        std::string LoadedPath;          // e.g. C:\Users\...\Temp\version.dll

        // The canonical "real" path the OS would have resolved this module name to
        std::string ExpectedSystemPath;  // e.g. C:\Windows\System32\version.dll

        // Whether the loaded path differs from the expected system path
        bool        IsPathHijacked = false;

        // Whether the loaded DLL forwards some or all of its exports to another DLL
        bool        HasForwardedExports = false;

        // If forwarded, the target DLL name (e.g. "version_orig.dll", "reallib.dll")
        std::string ForwardTargetDll;

        // Export counts
        DWORD       LoadedExportCount    = 0;  // Exports in the suspect DLL
        DWORD       RealExportCount      = 0;  // Exports in the real system DLL (for comparison)

        // How many exports are forwarded (forwarding wrappers)
        DWORD       ForwardedExportCount = 0;

        // Signature info of the loaded DLL
        bool        LoadedIsSigned       = false;
        bool        LoadedIsMicrosoftSigned = false;
        std::string LoadedSignerSubject;

        // SHA-256 of the loaded DLL
        std::string LoadedSHA256;

        // Detected DLL Proxy technique
        // e.g. "SEARCH_ORDER_HIJACK", "KNOWN_PROXY_WRAPPER", "EXPORT_FORWARD_SHIM"
        std::string ProxyTechnique;

        // "CRITICAL", "HIGH", "MEDIUM"
        std::string Severity;
        std::string Description;
    };

    // Scan all loaded modules in a specific process for DLL proxy / hijack indicators
    std::vector<DLLProxyDetection> ScanProcessDLLProxy(DWORD pid, const std::string& procName);

    // Scan all running processes
    std::vector<DLLProxyDetection> ScanAllProcessesDLLProxy();
}
