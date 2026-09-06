#include "RegistryArtifactScanner.hpp"
#include <iostream>
#include <algorithm>
#include <vector>

namespace RegistryArtifactScanner {

    static std::string ToLower(const std::string& str) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower;
    }

    static bool IsLegitimateSystemUpdater(const std::string& lowerPath) {
        static const std::vector<std::string> legitPatterns = {
            "setup", "installer", "update", "vc_redist", "dxwebsetup", "chrome", "msedge",
            "discord", "git", "node", "spotify", "steam", "visualstudio", "dotnet", "onedrive",
            "teams", "slack", "cursor", "gemini", "antigravity", "msbuild", "vcredist", "python",
            "rust", "winget", "driverbooster", "nvidia", "geforce", "radeon", "intel", "microsoft"
        };
        for (const auto& pat : legitPatterns) {
            if (lowerPath.find(pat) != std::string::npos) return true;
        }
        return false;
    }

    static bool IsGenericSuspiciousRegistryExecution(const std::string& rawPath, std::string& outReason, std::string& outSeverity) {
        std::string lower = ToLower(rawPath);

        // 1. Check if executable was run from a temporary or volatile user directory
        if (lower.find("\\appdata\\local\\temp\\") != std::string::npos ||
            lower.find("\\temp\\") != std::string::npos ||
            lower.find("\\users\\public\\") != std::string::npos) {
            
            // Skip legitimate software installers/updaters
            if (IsLegitimateSystemUpdater(lower)) {
                return false;
            }

            // Check if the file still exists on disk
            WCHAR widePath[MAX_PATH] = { 0 };
            MultiByteToWideChar(CP_UTF8, 0, rawPath.c_str(), -1, widePath, MAX_PATH);

            DWORD attr = GetFileAttributesW(widePath);
            if (attr == INVALID_FILE_ATTRIBUTES) {
                outReason = "Anti-Forensic Trace: Suspicious executable '" + rawPath + "' was executed from a temporary path and deleted from disk to evade forensic detection.";
                outSeverity = "HIGH";
                return true;
            }
            else {
                outReason = "Volatile Execution: Executable '" + rawPath + "' was launched from a temporary / staging folder.";
                outSeverity = "MEDIUM";
                return true;
            }
        }

        // 2. Check for known cheat keywords
        static const std::vector<std::string> patterns = {
            "cruz", "renault", "finalexp", "speedhack", "aimbot", "redeye", "red-eye",
            "xenos", "processhacker", "cheatengine", "kdmapper", "kdu", "blackbone",
            "winverb", "zwswap", "rawdriver", "dragpremium", "sniperinternal",
            "injector", "bypass", "spoofer", "dumper", "extremeinject"
        };

        for (const auto& p : patterns) {
            if (lower.find(p) != std::string::npos) {
                outReason = "Known cheat pattern match ('" + p + "') in registry execution record: " + rawPath;
                outSeverity = "CRITICAL";
                return true;
            }
        }

        return false;
    }

    static void ScanKeyValues(HKEY hRoot, const std::wstring& subKey, const std::string& rootName, const std::string& category, std::vector<RegArtifactDetection>& detections) {
        HKEY hKey;
        if (RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

        WCHAR valName[1024];
        DWORD valNameLen = 1024;
        DWORD index = 0;

        while (RegEnumValueW(hKey, index, valName, &valNameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            char valNameBuf[1024] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, valName, -1, valNameBuf, 1024, NULL, NULL);
            std::string nameA = valNameBuf;

            std::string reason, severity;
            if (IsGenericSuspiciousRegistryExecution(nameA, reason, severity)) {
                RegArtifactDetection d;
                char subKeyBuf[512] = { 0 };
                WideCharToMultiByte(CP_UTF8, 0, subKey.c_str(), -1, subKeyBuf, 512, NULL, NULL);
                d.KeyPath = rootName + "\\" + subKeyBuf;
                d.ValueName = nameA;
                d.ArtifactType = category;
                d.Severity = severity;
                d.Description = reason;
                detections.push_back(d);
            }

            valNameLen = 1024;
            index++;
        }

        RegCloseKey(hKey);
    }

    std::vector<RegArtifactDetection> ScanRegistryArtifacts() {
        std::vector<RegArtifactDetection> detections;

        // 1. MuiCache Execution Traces
        ScanKeyValues(HKEY_CURRENT_USER, L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", "HKCU", "MUICACHE_EXECUTION_RECORD", detections);

        // 2. AppCompatFlags Compatibility Assistant Store
        ScanKeyValues(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store", "HKCU", "COMPAT_ASSISTANT_STORE", detections);

        // 3. Background Activity Moderator (BAM) Execution Traces
        HKEY hBam;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings", 0, KEY_READ, &hBam) == ERROR_SUCCESS) {
            WCHAR subKeyName[256];
            DWORD subKeyLen = 256;
            DWORD i = 0;
            while (RegEnumKeyExW(hBam, i, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                std::wstring userBamPath = L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\" + std::wstring(subKeyName);
                ScanKeyValues(HKEY_LOCAL_MACHINE, userBamPath, "HKLM", "BAM_KERNEL_EXECUTION_LOG", detections);
                subKeyLen = 256;
                i++;
            }
            RegCloseKey(hBam);
        }

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings", 0, KEY_READ, &hBam) == ERROR_SUCCESS) {
            WCHAR subKeyName[256];
            DWORD subKeyLen = 256;
            DWORD i = 0;
            while (RegEnumKeyExW(hBam, i, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                std::wstring userBamPath = L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings\\" + std::wstring(subKeyName);
                ScanKeyValues(HKEY_LOCAL_MACHINE, userBamPath, "HKLM", "BAM_KERNEL_EXECUTION_LOG", detections);
                subKeyLen = 256;
                i++;
            }
            RegCloseKey(hBam);
        }

        return detections;
    }
}
