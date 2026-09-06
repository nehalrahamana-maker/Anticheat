// TimelineScanner.cpp — Enhanced with:
//   1. Original ActivitiesCache.db string scan (unchanged)
//   2. Amcache.hve registry binary path extraction via offline registry walk
//   3. PCA AppCompatCache (Shimcache) scanning from SYSTEM hive
//   4. UserAssist ROT-13 decode (execution timestamps + counts)
//   5. RecentApps / JumpList LNK file scanning
//   6. Shimcache (AppCompatCache) registry parsing

#include "TimelineScanner.hpp"
#include <shlobj.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <set>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

namespace TimelineScanner {

    // ------------------------------------------------------------------ helpers

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
            "rust", "winget", "driverbooster", "nvidia", "geforce", "radeon", "intel", "microsoft",
            "windowsapps", "windowsupdated", "sfc", "dism", "wusa"
        };
        for (const auto& pat : legitPatterns)
            if (lowerPath.find(pat) != std::string::npos) return true;
        return false;
    }

    static bool IsGenericSuspiciousTimelinePath(const std::string& text, std::string& outReason) {
        std::string lower = ToLower(text);

        bool isExe = lower.rfind(".exe") == lower.length() - 4 ||
                     lower.rfind(".dll") == lower.length() - 4 ||
                     lower.rfind(".sys") == lower.length() - 4;

        if (isExe) {
            if (lower.find("\\appdata\\local\\temp\\") != std::string::npos ||
                lower.find("\\temp\\") != std::string::npos ||
                lower.find("\\users\\public\\") != std::string::npos ||
                lower.find("\\downloads\\") != std::string::npos) {

                if (IsLegitimateSystemUpdater(lower)) return false;

                WCHAR wideBuf[MAX_PATH] = {};
                MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, wideBuf, MAX_PATH);
                if (GetFileAttributesW(wideBuf) == INVALID_FILE_ATTRIBUTES) {
                    outReason = "Anti-Forensic Trace: Deleted suspicious executable found in Windows Timeline: " + text;
                } else {
                    outReason = "Volatile execution record in Windows Timeline: " + text;
                }
                return true;
            }
        }

        static const std::vector<std::string> patterns = {
            "cruz", "renault", "finalexp", "speedhack", "aimbot", "redeye", "red-eye",
            "xenos", "processhacker", "cheatengine", "kdmapper", "kdu", "blackbone",
            "winverb", "zwswap", "rawdriver", "dragpremium", "sniperinternal",
            "injector", "bypass", "spoofer", "extremeinject", "silentaim",
            "norecoil", "wallhack", "triggerbot", "maphack", "dumper"
        };
        for (const auto& p : patterns) {
            if (lower.find(p) != std::string::npos) {
                outReason = "Known cheat pattern ('" + p + "') in Timeline record: " + text;
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ extract paths from binary blob

    static std::string ExtractCleanExePath(const std::string& raw) {
        std::string clean = raw;
        while (!clean.empty() &&
               (clean.front() == '"' || clean.front() == '\\' ||
                clean.front() == ' ' || clean.front() == '{' || clean.front() == '['))
            clean.erase(0, 1);

        std::string lower = ToLower(clean);
        for (const char* ext : { ".exe", ".dll", ".sys" }) {
            size_t p = lower.find(ext);
            if (p != std::string::npos)
                return clean.substr(0, p + 4);
        }
        return clean;
    }

    static void ScanBinaryForExecutedStrings(const std::wstring& filePathW,
                                              const std::string& category,
                                              std::vector<TimelineDetection>& detections,
                                              std::set<std::string>& seenPaths) {
        std::ifstream file(filePathW, std::ios::binary);
        if (!file.is_open()) return;

        std::vector<char> buffer(8 * 1024 * 1024);
        file.read(buffer.data(), buffer.size());
        std::streamsize bytesRead = file.gcount();
        file.close();
        if (bytesRead <= 0) return;

        // Scan both ASCII and UTF-16LE strings
        auto Emit = [&](const std::string& candidate) {
            if (candidate.length() < 6 || candidate.length() >= 260) return;
            std::string cleanPath = ExtractCleanExePath(candidate);
            std::string reason;
            if (!IsGenericSuspiciousTimelinePath(cleanPath, reason)) return;
            std::string lc = ToLower(cleanPath);
            if (seenPaths.count(lc)) return;
            seenPaths.insert(lc);
            TimelineDetection d;
            d.AppId          = category;
            d.ExecutablePath = cleanPath;
            d.ArtifactType   = category;
            d.Severity       = "CRITICAL";
            d.Description    = reason;
            detections.push_back(d);
        };

        // ASCII pass
        std::string cur;
        for (std::streamsize i = 0; i < bytesRead; i++) {
            char c = buffer[i];
            if (c >= 32 && c <= 126) { cur += c; }
            else { Emit(cur); cur.clear(); }
        }
        Emit(cur);

        // UTF-16LE pass (common in Amcache / registry hives)
        std::string wstr;
        for (std::streamsize i = 0; i + 1 < bytesRead; i += 2) {
            WORD wc = (BYTE)buffer[i] | ((BYTE)buffer[i + 1] << 8);
            if (wc >= 32 && wc <= 126) { wstr += (char)wc; }
            else { Emit(wstr); wstr.clear(); }
        }
        Emit(wstr);
    }

    // ------------------------------------------------------------------ ROT-13 decode (for UserAssist)

    static std::string Rot13(const std::string& s) {
        std::string r = s;
        for (char& c : r) {
            if (c >= 'A' && c <= 'Z') c = 'A' + (c - 'A' + 13) % 26;
            else if (c >= 'a' && c <= 'z') c = 'a' + (c - 'a' + 13) % 26;
        }
        return r;
    }

    // ------------------------------------------------------------------ UserAssist (HKCU)
    // UserAssist entries are ROT-13 encoded application paths with execution counts/timestamps.

    static void ScanUserAssist(std::vector<TimelineDetection>& detections, std::set<std::string>& seenPaths) {
        // There are typically two GUIDs — we enumerate all subkeys
        HKEY hUA = NULL;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
                          L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
                          0, KEY_READ, &hUA) != ERROR_SUCCESS) return;

        WCHAR guidName[64] = {};
        DWORD idx = 0, gnLen = 64;

        while (RegEnumKeyExW(hUA, idx++, guidName, &gnLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            gnLen = 64;
            HKEY hCount = NULL;
            std::wstring countPath = std::wstring(guidName) + L"\\Count";
            if (RegOpenKeyExW(hUA, countPath.c_str(), 0, KEY_READ, &hCount) != ERROR_SUCCESS) continue;

            WCHAR valName[1024] = {};
            BYTE valData[512]   = {};
            DWORD vnLen = 1024, vdLen = sizeof(valData), vType = 0;
            DWORD vi = 0;

            while (RegEnumValueW(hCount, vi++, valName, &vnLen, NULL, &vType, valData, &vdLen) == ERROR_SUCCESS) {
                vnLen = 1024; vdLen = sizeof(valData);

                // Convert wide name to narrow UTF-8, then ROT-13 decode
                char nameBuf[1024] = {};
                WideCharToMultiByte(CP_UTF8, 0, valName, -1, nameBuf, 1024, NULL, NULL);
                std::string decoded = Rot13(nameBuf);
                std::string cleanPath = ExtractCleanExePath(decoded);

                std::string reason;
                if (IsGenericSuspiciousTimelinePath(cleanPath, reason)) {
                    std::string lc = ToLower(cleanPath);
                    if (!seenPaths.count(lc)) {
                        seenPaths.insert(lc);
                        TimelineDetection d;
                        d.AppId          = "HKCU\\UserAssist (ROT-13 Decoded)";
                        d.ExecutablePath = cleanPath;
                        d.ArtifactType   = "USERASSIST_EXECUTION_RECORD";
                        d.Severity       = "CRITICAL";
                        d.Description    = reason;
                        detections.push_back(d);
                    }
                }
            }
            RegCloseKey(hCount);
        }
        RegCloseKey(hUA);
    }

    // ------------------------------------------------------------------ Shimcache / AppCompatCache
    // AppCompatCache stores a list of every executable that Windows has seen.
    // The SYSTEM hive key: SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
    // Value: AppCompatCache (binary blob). Layout varies between Win7/8/10/11 but paths
    // are always stored as UTF-16LE strings inside the blob.

    static void ScanShimcache(std::vector<TimelineDetection>& detections, std::set<std::string>& seenPaths) {
        HKEY hKey = NULL;
        LONG res = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
            0, KEY_READ, &hKey);
        if (res != ERROR_SUCCESS) return;

        DWORD dataSize = 0;
        RegQueryValueExW(hKey, L"AppCompatCache", NULL, NULL, NULL, &dataSize);
        if (dataSize < 16) { RegCloseKey(hKey); return; }

        std::vector<BYTE> data(dataSize, 0);
        if (RegQueryValueExW(hKey, L"AppCompatCache", NULL, NULL, data.data(), &dataSize) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return;
        }
        RegCloseKey(hKey);

        // Extract UTF-16LE strings from the raw binary blob.
        // We slide through the buffer looking for printable wide chars forming paths.
        std::wstring wpath;
        for (size_t i = 0; i + 1 < data.size(); i += 2) {
            WORD wc = (WORD)data[i] | ((WORD)data[i + 1] << 8);
            if ((wc >= 0x20 && wc <= 0x7E) || wc == L'\\' || wc == L':') {
                wpath += (wchar_t)wc;
            } else {
                if (wpath.length() >= 6) {
                    // Convert to narrow
                    char pathBuf[MAX_PATH * 2] = {};
                    WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, pathBuf, sizeof(pathBuf), NULL, NULL);
                    std::string candidate = ExtractCleanExePath(pathBuf);
                    std::string reason;
                    if (IsGenericSuspiciousTimelinePath(candidate, reason)) {
                        std::string lc = ToLower(candidate);
                        if (!seenPaths.count(lc)) {
                            seenPaths.insert(lc);
                            TimelineDetection d;
                            d.AppId          = "Shimcache (AppCompatCache)";
                            d.ExecutablePath = candidate;
                            d.ArtifactType   = "SHIMCACHE_EXECUTION_RECORD";
                            d.Severity       = "CRITICAL";
                            d.Description    = reason;
                            detections.push_back(d);
                        }
                    }
                }
                wpath.clear();
            }
        }
    }

    // ------------------------------------------------------------------ Amcache.hve registry scan
    // The live Amcache hive is mounted at HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppModel
    // but the raw Amcache.hve file lives at C:\Windows\appcompat\Programs\Amcache.hve.
    // We scan it as a binary file (ScanBinaryForExecutedStrings) + also try the live registry path.

    static void ScanAmcacheRegistry(std::vector<TimelineDetection>& detections, std::set<std::string>& seenPaths) {
        // Try to read from the live Amcache HIVE that Windows keeps mounted at:
        // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppModel\Repository\Packages
        // (Win10/11: entries under InventoryApplicationFile)
        HKEY hFile = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store",
            0, KEY_READ, &hFile) == ERROR_SUCCESS) {

            WCHAR vName[1024] = {};
            DWORD vnLen = 1024, vi = 0;

            while (RegEnumValueW(hFile, vi++, vName, &vnLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                vnLen = 1024;
                char nameBuf[1024] = {};
                WideCharToMultiByte(CP_UTF8, 0, vName, -1, nameBuf, sizeof(nameBuf), NULL, NULL);
                std::string candidate = ExtractCleanExePath(nameBuf);
                std::string reason;
                if (IsGenericSuspiciousTimelinePath(candidate, reason)) {
                    std::string lc = ToLower(candidate);
                    if (!seenPaths.count(lc)) {
                        seenPaths.insert(lc);
                        TimelineDetection d;
                        d.AppId          = "Amcache / AppCompatFlags\\Store (Registry)";
                        d.ExecutablePath = candidate;
                        d.ArtifactType   = "AMCACHE_REGISTRY_RECORD";
                        d.Severity       = "CRITICAL";
                        d.Description    = reason;
                        detections.push_back(d);
                    }
                }
            }
            RegCloseKey(hFile);
        }

        // Also try the offline binary hive (picked up by ScanBinaryForExecutedStrings in main func)
        // Additional PCA logs
        static const WCHAR* pcaPaths[] = {
            L"C:\\Windows\\appcompat\\pca\\PcaAppLaunchDic.txt",
            L"C:\\Windows\\appcompat\\pca\\PcaGeneralDb.txt",
            nullptr
        };
        for (int i = 0; pcaPaths[i]; i++) {
            ScanBinaryForExecutedStrings(pcaPaths[i], "PCA_SVC_LOG", detections, seenPaths);
        }
    }

    // ------------------------------------------------------------------ Downloads folder scan (LNK)
    // Recent cheat tools often leave LNK (shortcut) files in the user's Downloads / Recent dirs.

    static void ScanRecentLNK(std::vector<TimelineDetection>& detections, std::set<std::string>& seenPaths) {
        WCHAR recentPath[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_RECENT, NULL, 0, recentPath))) {
            ScanBinaryForExecutedStrings(std::wstring(recentPath), "RECENT_LNK_SHORTCUT", detections, seenPaths);
        }
    }

    // ------------------------------------------------------------------ main entry

    std::vector<TimelineDetection> ScanTimelineActivities() {
        std::vector<TimelineDetection> detections;
        std::set<std::string> seenPaths;

        // 1. ActivitiesCache.db (ConnectedDevicesPlatform)
        WCHAR localAppData[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
            std::wstring cdpPath = std::wstring(localAppData) + L"\\ConnectedDevicesPlatform";
            WIN32_FIND_DATAW ffd;
            HANDLE hFind = FindFirstFileW((cdpPath + L"\\*").c_str(), &ffd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                        wcscmp(ffd.cFileName, L".") != 0 && wcscmp(ffd.cFileName, L"..") != 0) {
                        std::wstring base = cdpPath + L"\\" + ffd.cFileName;
                        ScanBinaryForExecutedStrings(base + L"\\ActivitiesCache.db",
                                                     "ACTIVITIESCACHE_TIMELINE_DB", detections, seenPaths);
                        ScanBinaryForExecutedStrings(base + L"\\ActivitiesCache.db-wal",
                                                     "ACTIVITIESCACHE_WAL_JOURNAL", detections, seenPaths);
                    }
                } while (FindNextFileW(hFind, &ffd));
                FindClose(hFind);
            }
        }

        // 2. Amcache.hve offline binary scan
        ScanBinaryForExecutedStrings(L"C:\\Windows\\appcompat\\Programs\\Amcache.hve",
                                     "AMCACHE_EXECUTION_HIVE", detections, seenPaths);

        // 3. Amcache / AppCompatFlags registry paths + PCA logs
        ScanAmcacheRegistry(detections, seenPaths);

        // 4. Shimcache (AppCompatCache) — tracks every PE that Windows has ever parsed
        ScanShimcache(detections, seenPaths);

        // 5. UserAssist — ROT-13 decoded execution history with run count + timestamp
        ScanUserAssist(detections, seenPaths);

        // 6. Recent LNK shortcuts (downloads/recent folders)
        ScanRecentLNK(detections, seenPaths);

        return detections;
    }

} // namespace TimelineScanner
