#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace DriverScanner {

    struct DriverServiceDetection {
        std::string ServiceName;
        std::wstring DisplayName;
        std::wstring ImagePath;
        std::wstring ResolvedPath;
        DWORD StartType; // 0 = Boot, 1 = System, 2 = Auto, 3 = Manual, 4 = Disabled
        std::string StartTypeStr;
        DWORD ServiceType;
        bool FileExists;
        bool IsSigned;
        bool IsMicrosoftSigned;
        std::string SignerSubject;
        std::string FileSHA256;
        bool IsKnownCheatPattern;
        std::string Severity; // "CRITICAL", "HIGH", "MEDIUM", "LOW"
        std::string Description;
    };

    struct LoadedDriverDetection {
        std::string DriverName;
        std::wstring DriverPath;
        ULONG_PTR ImageBase;
        DWORD ImageSize;
        bool FileExists;
        bool IsSigned;
        bool IsMicrosoftSigned;
        bool IsVulnerableBYOVD;
        bool IsStagingFolder;
        std::string SignerSubject;
        std::string Severity; // "CRITICAL", "WARNING", "INFO"
        std::string Description;
    };

    struct MappedDriverDetection {
        std::string DriverOrToolName;
        std::string DetectionSource; // "BYOVD_EXPLOIT_DRIVER", "VOLATILE_DRIVER_STAGING", "UNBACKED_KERNEL_DRIVER", "DSE_DISABLED"
        std::string StagingPath;
        std::string Severity; // "CRITICAL", "WARNING"
        std::string Description;
    };

    struct HVCISecurityStatus {
        bool VBSEnabled;
        bool HVCIEnabled;
        bool SecureBootEnabled;
        std::string StatusSummary;
        std::string RemediationRecommendation;
    };

    // Scan all installed Windows kernel driver services in registry
    std::vector<DriverServiceDetection> ScanDriverServices();

    // Scan all currently loaded kernel device drivers in Ring 0 (EnumDeviceDrivers)
    std::vector<LoadedDriverDetection> ScanLoadedKernelDrivers();

    // Scan for manual mapped driver indicators (kdmapper, KDU, BYOVD vulnerable exploit drivers, staging paths, DSE policy)
    std::vector<MappedDriverDetection> ScanMappedDriverForensics();

    // Check system VBS / HVCI configuration
    HVCISecurityStatus CheckHVCIStatus();

    // Helper to disable a malicious boot service
    bool DisableService(const std::string& serviceName);
}
