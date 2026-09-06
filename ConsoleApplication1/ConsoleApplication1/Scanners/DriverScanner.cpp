#include "DriverScanner.hpp"
#include "PEParser.hpp"
#include "SigScanner.hpp"
#include <psapi.h>
#include <shlwapi.h>
#include <iostream>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

namespace DriverScanner {

    static std::string WideToNarrow(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        char buf[MAX_PATH] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, buf, MAX_PATH, NULL, NULL);
        return std::string(buf);
    }

    static std::wstring ResolveDriverPath(const std::wstring& rawPath) {
        if (rawPath.empty()) return L"";

        std::wstring path = rawPath;

        // Trim leading and trailing quotes / whitespace
        while (!path.empty() && (path.front() == L'\"' || path.front() == L' ' || path.front() == L'\\')) {
            if (path.rfind(L"\\??\\", 0) == 0) {
                path = path.substr(4);
                break;
            }
            if (path.rfind(L"\\SystemRoot\\", 0) == 0) {
                path = L"C:\\Windows\\" + path.substr(12);
                break;
            }
            if (path.front() == L'\"' || path.front() == L' ') {
                path.erase(0, 1);
            }
            else {
                break;
            }
        }

        while (!path.empty() && (path.back() == L'\"' || path.back() == L' ')) {
            path.pop_back();
        }

        if (path.rfind(L"\\??\\", 0) == 0) {
            path = path.substr(4);
        }
        else if (path.rfind(L"\\SystemRoot\\", 0) == 0) {
            path = L"C:\\Windows\\" + path.substr(12);
        }
        else if (path.rfind(L"system32\\", 0) == 0 || path.rfind(L"System32\\", 0) == 0) {
            path = L"C:\\Windows\\" + path;
        }

        // Expand environment variables
        WCHAR expanded[MAX_PATH] = { 0 };
        if (ExpandEnvironmentStringsW(path.c_str(), expanded, MAX_PATH) > 0) {
            return std::wstring(expanded);
        }
        return path;
    }

    static std::string StartTypeToString(DWORD start) {
        switch (start) {
        case 0: return "0 (BOOT_START - Loads before Windows GUI)";
        case 1: return "1 (SYSTEM_START - Loads with Kernel/OS)";
        case 2: return "2 (AUTO_START - Normal Boot)";
        case 3: return "3 (DEMAND_START - Manual)";
        case 4: return "4 (DISABLED)";
        default: return std::to_string(start);
        }
    }

    static bool IsKnownCheatServiceName(const std::string& name) {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        static const std::vector<std::string> suspiciousPatterns = {
            "winverb",
            "zwswap",
            "driver_swap",
            "rawdriver",
            "capcom",
            "procexp152",
            "dbutil_2_3",
            "rtcore64",
            "mhyprot2",
            "iqvw64e",
            "asiodrv",
            "blackbone",
            "kdmapper",
            "kdu_driver",
            "eac_bypass",
            "vgk_bypass",
            "renault",
            "renaultdriver",
            "cruz_bypass",
            "zwswapcert"
        };

        for (const auto& pat : suspiciousPatterns) {
            if (lower == pat || lower.find(pat) != std::string::npos) return true;
        }
        if (lower == "gdrv" || lower == "gdrv.sys") return true;
        return false;
    }

    std::vector<DriverServiceDetection> ScanDriverServices() {
        std::vector<DriverServiceDetection> detections;

        HKEY hServicesKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hServicesKey) != ERROR_SUCCESS) {
            return detections;
        }

        WCHAR subKeyName[256];
        DWORD idx = 0;
        DWORD nameLen = 256;

        while (RegEnumKeyExW(hServicesKey, idx++, subKeyName, &nameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            nameLen = 256;

            HKEY hSubKey = NULL;
            if (RegOpenKeyExW(hServicesKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                DWORD type = 0, start = 0;
                DWORD typeSize = sizeof(DWORD), startSize = sizeof(DWORD);
                WCHAR imagePath[MAX_PATH] = { 0 };
                DWORD pathSize = sizeof(imagePath);
                WCHAR displayName[256] = { 0 };
                DWORD dispSize = sizeof(displayName);

                RegQueryValueExW(hSubKey, L"Type", NULL, NULL, (LPBYTE)&type, &typeSize);
                RegQueryValueExW(hSubKey, L"Start", NULL, NULL, (LPBYTE)&start, &startSize);
                RegQueryValueExW(hSubKey, L"ImagePath", NULL, NULL, (LPBYTE)imagePath, &pathSize);
                RegQueryValueExW(hSubKey, L"DisplayName", NULL, NULL, (LPBYTE)displayName, &dispSize);

                RegCloseKey(hSubKey);

                char szSvcName[256] = { 0 };
                WideCharToMultiByte(CP_UTF8, 0, subKeyName, -1, szSvcName, sizeof(szSvcName), NULL, NULL);
                std::string svcName(szSvcName);
                std::wstring wsImagePath(imagePath);

                // Filter for kernel driver services (Type == 1 / 2) or services having .sys in ImagePath
                bool isDriver = (type == 1 || type == 2 || wsImagePath.find(L".sys") != std::wstring::npos);
                if (!isDriver) continue;

                DriverServiceDetection det = {};
                det.ServiceName = svcName;
                det.DisplayName = displayName;
                det.ImagePath = wsImagePath;
                det.ResolvedPath = ResolveDriverPath(wsImagePath);
                det.StartType = start;
                det.StartTypeStr = StartTypeToString(start);
                det.ServiceType = type;
                det.FileExists = false;
                det.IsSigned = false;
                det.IsMicrosoftSigned = false;
                det.IsKnownCheatPattern = IsKnownCheatServiceName(svcName);

                bool isSystemDriverFolder = (det.ResolvedPath.find(L"C:\\Windows\\System32\\drivers") == 0 ||
                    det.ResolvedPath.find(L"C:\\Windows\\system32\\drivers") == 0 ||
                    det.ResolvedPath.find(L"C:\\Windows\\System32\\DriverStore") == 0 ||
                    det.ResolvedPath.find(L"C:\\Windows\\System32\\") == 0 ||
                    det.ResolvedPath.find(L"C:\\Windows\\SysWOW64\\") == 0);

                // Optimization: only inspect PE cert on boot drivers, suspicious names, or drivers outside Windows folder
                bool shouldInspectCert = (start <= 1 || det.IsKnownCheatPattern || !isSystemDriverFolder);

                if (!det.ResolvedPath.empty()) {
                    DWORD attr = GetFileAttributesW(det.ResolvedPath.c_str());
                    det.FileExists = (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));

                    if (det.FileExists && shouldInspectCert) {
                        PE::PEImage pe;
                        if (pe.LoadFromFile(det.ResolvedPath)) {
                            det.FileSHA256 = PE::PEImage::ComputeSHA256(pe.GetRawBuffer());
                            auto cert = pe.ParseCertificate(det.ResolvedPath);
                            det.IsSigned = cert.HasCertificate && cert.IsTrusted;
                            det.IsMicrosoftSigned = cert.IsMicrosoftSigned;
                            det.SignerSubject = cert.SubjectName;
                        }
                    }
                }

                if (isSystemDriverFolder && !det.IsSigned) {
                    det.IsSigned = true; // Catalog signed system driver
                    det.IsMicrosoftSigned = true;
                }

                // Check severity heuristics - ONLY add genuine security anomalies
                if (det.IsKnownCheatPattern) {
                    det.Severity = "CRITICAL";
                    det.Description = "KNOWN ROOTKIT / DRIVER-SWAP PATTERN ('" + svcName + "') detected in system driver services! Boot persistence active.";
                    detections.push_back(det);
                }
                else if (start <= 1 && det.FileExists && !det.IsSigned && !isSystemDriverFolder) { // Boot or System start + unsigned non-system folder
                    det.Severity = "CRITICAL";
                    det.Description = "Unsigned kernel driver configured for Boot/System Start outside Windows drivers folder (" + det.StartTypeStr + "). Potential vulnerable/swapped driver.";
                    detections.push_back(det);
                }
                else if (start <= 1 && det.FileExists && !isSystemDriverFolder && !det.IsMicrosoftSigned && !det.IsSigned) {
                    det.Severity = "HIGH";
                    det.Description = "Third-party unsigned driver configured for early boot load outside System32 directory: " + WideToNarrow(det.ResolvedPath);
                    detections.push_back(det);
                }
            }
        }

        RegCloseKey(hServicesKey);
        return detections;
    }

    HVCISecurityStatus CheckHVCIStatus() {
        HVCISecurityStatus status;
        status.VBSEnabled = false;
        status.HVCIEnabled = false;
        status.SecureBootEnabled = false;

        // Check Secure Boot
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD val = 0, sz = sizeof(DWORD);
            if (RegQueryValueExW(hKey, L"UEFISecureBootEnabled", NULL, NULL, (LPBYTE)&val, &sz) == ERROR_SUCCESS) {
                status.SecureBootEnabled = (val == 1);
            }
            RegCloseKey(hKey);
        }

        // Check DeviceGuard (VBS)
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD val = 0, sz = sizeof(DWORD);
            if (RegQueryValueExW(hKey, L"EnableVirtualizationBasedSecurity", NULL, NULL, (LPBYTE)&val, &sz) == ERROR_SUCCESS) {
                status.VBSEnabled = (val == 1);
            }
            RegCloseKey(hKey);
        }

        // Check HVCI (Hypervisor-protected Code Integrity)
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD val = 0, sz = sizeof(DWORD);
            if (RegQueryValueExW(hKey, L"Enabled", NULL, NULL, (LPBYTE)&val, &sz) == ERROR_SUCCESS) {
                status.HVCIEnabled = (val == 1);
            }
            RegCloseKey(hKey);
        }

        if (status.HVCIEnabled) {
            status.StatusSummary = "PROTECTED: HVCI (Memory Integrity) is ENABLED. Kernel code pages are hardware-enforced read-only. Driver Swapping (MDL write) is blocked by Hyper-V.";
            status.RemediationRecommendation = "None needed. System has strong kernel integrity enforcement.";
        }
        else {
            status.StatusSummary = "VULNERABLE: HVCI (Memory Integrity) is DISABLED! Kernel memory can be modified via MDL overwrites (Driver-Swapping attack).";
            status.RemediationRecommendation = "Enable 'Memory Integrity' (Core Isolation) in Windows Security -> Device Security -> Core isolation details.";
        }

        return status;
    }

    std::vector<LoadedDriverDetection> ScanLoadedKernelDrivers() {
        std::vector<LoadedDriverDetection> detections;
        LPVOID drivers[2048];
        DWORD cbNeeded = 0;

        if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
            int cDrivers = cbNeeded / sizeof(drivers[0]);
            for (int i = 0; i < cDrivers; i++) {
                if (!drivers[i]) continue;

                WCHAR szDriverName[MAX_PATH] = { 0 };
                WCHAR szDriverPath[MAX_PATH] = { 0 };

                GetDeviceDriverBaseNameW(drivers[i], szDriverName, MAX_PATH);
                GetDeviceDriverFileNameW(drivers[i], szDriverPath, MAX_PATH);

                std::wstring wsName(szDriverName);
                std::wstring wsRawPath(szDriverPath);
                std::wstring wsResolved = ResolveDriverPath(wsRawPath);

                std::string sName = WideToNarrow(wsName);
                std::string sLowerName = sName;
                std::transform(sLowerName.begin(), sLowerName.end(), sLowerName.begin(), ::tolower);

                std::string sPath = WideToNarrow(wsResolved);
                std::string sLowerPath = sPath;
                std::transform(sLowerPath.begin(), sLowerPath.end(), sLowerPath.begin(), ::tolower);

                DWORD fileAttr = GetFileAttributesW(wsResolved.c_str());
                bool fileExists = (fileAttr != INVALID_FILE_ATTRIBUTES && !(fileAttr & FILE_ATTRIBUTE_DIRECTORY));

                // Ignore Windows crash dump / hibernation kernel modules
                bool isCrashDumpDriver = (sLowerName.rfind("dump_", 0) == 0 || sLowerName.rfind("hiber_", 0) == 0);
                if (isCrashDumpDriver) continue;

                // Check staging / temp folders
                bool isStaging = (sLowerPath.find("\\temp\\") != std::string::npos ||
                                  sLowerPath.find("\\appdata\\") != std::string::npos ||
                                  sLowerPath.find("\\downloads\\") != std::string::npos ||
                                  sLowerPath.find("\\users\\") != std::string::npos);

                bool isSystemLocation = (sLowerPath.find("\\system32\\drivers\\") != std::string::npos ||
                                         sLowerPath.find("\\system32\\driverstore\\") != std::string::npos ||
                                         sLowerPath.find("\\windows\\system32\\") != std::string::npos ||
                                         sLowerPath.find("\\windows\\syswow64\\") != std::string::npos);

                // Check BYOVD database
                bool isBYOVD = IsKnownCheatServiceName(sLowerName);

                // Check Signature
                SigScanner::SignatureDetection sigDet = {};
                bool isSigned = false;
                bool isMsSigned = false;
                std::string signer = "Unknown / Unsigned";

                if (fileExists) {
                    sigDet = SigScanner::ScanBinarySignature(wsResolved);
                    isSigned = sigDet.IsTrusted;
                    signer = sigDet.SignerSubject;
                    std::string lowerSigner = signer;
                    std::transform(lowerSigner.begin(), lowerSigner.end(), lowerSigner.begin(), ::tolower);
                    if (lowerSigner.find("microsoft") != std::string::npos || lowerSigner.find("windows") != std::string::npos) {
                        isMsSigned = true;
                    }
                }

                // If in standard Windows System32/DriverStore without BYOVD matches, consider it clean system driver
                if (isSystemLocation && !isBYOVD && !isStaging) {
                    isSigned = true;
                }

                // If driver has true anomalies (unsigned outside system, deleted non-dump file, staging path, or BYOVD exploit), record detection
                if ((!fileExists && !isCrashDumpDriver) || (!isSigned && !isSystemLocation) || isStaging || isBYOVD) {
                    LoadedDriverDetection det = {};
                    det.DriverName = sName;
                    det.DriverPath = wsResolved;
                    det.ImageBase = (ULONG_PTR)drivers[i];
                    det.ImageSize = 0;
                    det.FileExists = fileExists;
                    det.IsSigned = isSigned;
                    det.IsMicrosoftSigned = isMsSigned;
                    det.IsVulnerableBYOVD = isBYOVD;
                    det.IsStagingFolder = isStaging;
                    det.SignerSubject = signer;

                    std::stringstream ssHex;
                    ssHex << std::hex << std::uppercase << det.ImageBase;

                    if (!fileExists) {
                        det.Severity = "CRITICAL";
                        det.Description = "UNBACKED / VOLATILE DRIVER: Kernel driver is executing at base 0x" + 
                                          ssHex.str() + " but its disk binary was deleted (Manual Mapper Traces).";
                    }
                    else if (isBYOVD) {
                        det.Severity = "CRITICAL";
                        det.Description = "VULNERABLE BYOVD EXPLOIT DRIVER: Known exploitable mapper driver (" + sName + ") loaded in kernel memory.";
                    }
                    else if (!isSigned) {
                        det.Severity = "CRITICAL";
                        det.Description = "UNSIGNED KERNEL DRIVER: Binary executing in Ring 0 without valid Authenticode digital signature: " + sPath;
                    }
                    else if (isStaging) {
                        det.Severity = "WARNING";
                        det.Description = "NON-STANDARD DRIVER PATH: Driver loaded from user staging directory: " + sPath;
                    }

                    detections.push_back(det);
                }
            }
        }
        return detections;
    }

    std::vector<MappedDriverDetection> ScanMappedDriverForensics() {
        std::vector<MappedDriverDetection> detections;

        // 1. Check DSE (Driver Signature Enforcement) & Testsigning Status
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD testSigning = 0, sz = sizeof(DWORD);
            if (RegQueryValueExW(hKey, L"SystemTestSigning", NULL, NULL, (LPBYTE)&testSigning, &sz) == ERROR_SUCCESS) {
                if (testSigning == 1) {
                    MappedDriverDetection det = {};
                    det.DriverOrToolName = "Windows DSE Policy";
                    det.DetectionSource = "DSE_DISABLED";
                    det.Severity = "CRITICAL";
                    det.Description = "TESTSIGNING ACTIVE: Windows Driver Signature Enforcement is disabled via BCD / TestSigning mode!";
                    detections.push_back(det);
                }
            }
            RegCloseKey(hKey);
        }

        // 2. Scan Prefetch & Temp Directories for Known Mapper Binaries (kdmapper, KDU, gdrv)
        static const std::vector<std::string> mapperKeywords = {
            "kdmapper", "kdu", "drvmap", "zwswap", "map.sys", "gdrv.sys", "iqvw64e.sys", "rtcore64.sys", "dbutil_2_3.sys"
        };

        // Scan C:\Windows\Temp and User Temp for mapper binaries
        WCHAR winTempPath[MAX_PATH] = L"C:\\Windows\\Temp\\*.*";
        WIN32_FIND_DATAW ffd;
        HANDLE hFind = FindFirstFileW(winTempPath, &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::wstring fn = ffd.cFileName;
                    std::string sfn = WideToNarrow(fn);
                    std::string sfnLower = sfn;
                    std::transform(sfnLower.begin(), sfnLower.end(), sfnLower.begin(), ::tolower);

                    for (const auto& kw : mapperKeywords) {
                        if (sfnLower.find(kw) != std::string::npos) {
                            MappedDriverDetection det = {};
                            det.DriverOrToolName = sfn;
                            det.DetectionSource = "VOLATILE_DRIVER_STAGING";
                            det.StagingPath = "C:\\Windows\\Temp\\" + sfn;
                            det.Severity = "CRITICAL";
                            det.Description = "BYOVD / MANUAL MAPPER PAYLOAD IN STAGING: Staged exploit driver or mapper found in C:\\Windows\\Temp: " + sfn;
                            detections.push_back(det);
                            break;
                        }
                    }
                }
            } while (FindNextFileW(hFind, &ffd));
            FindClose(hFind);
        }

        return detections;
    }

    bool DisableService(const std::string& serviceName) {
        std::wstring ws(serviceName.begin(), serviceName.end());
        std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + ws;

        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            DWORD start = 4; // Disabled
            RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (const BYTE*)&start, sizeof(DWORD));
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }
}
