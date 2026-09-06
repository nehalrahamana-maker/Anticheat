// AmcacheScanner.cpp
// Parses the Windows Amcache.hve registry hive to find historical
// evidence of application execution including deleted cheats.
//
// Amcache records SHA1 hashes, file paths, and first execution times
// for every executable ever run on the system. It survives file deletion
// making it one of the most powerful forensic artifacts available.
//
// Registry path (offline hive): C:\Windows\AppCompat\Programs\Amcache.hve
// We load it as a registry hive using RegLoadKey and parse:
//   \Root\InventoryApplicationFile — one subkey per exe
//     Each subkey contains: Name, LowerCaseLongPath, FileId (SHA1), LinkDate

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "AmcacheScanner.hpp"
#include <shlwapi.h>
#include <algorithm>
#include <string>
#include <vector>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace AmcacheScanner {

    static const char* k_CheatKeywords[] = {
        "aimbot", "wallhack", "cheat", "inject", "hack", "bypass",
        "spoofer", "dumper", "loader", "triggerbot", "silentaim",
        "norecoil", "hdplayer", "hddplayer", "gva", "galib", "garv",
        "bstkvmm", "xenos", "kdmapper", "redengine", "flkbypass",
        "antiecho", "crusader", "hydron", "vegacheat", "ring1cheat",
        "hxcheats", "binarycheat", "venacy", "externhack", "manualmap",
        "doomsday", "finalexp", "novaclient", "grimclient", "skript",
        nullptr
    };

    // Known cheat SHA1 hashes (partial list — the field starts with "0000" + SHA1)
    static const char* k_KnownCheatHashes[] = {
        // These would be populated from a threat intel feed
        // Format as stored in Amcache: "0000" + 40 hex chars
        nullptr // sentinel
    };

    static const char* k_Whitelist[] = {
        "\\windows\\", "\\program files\\", "\\program files (x86)\\",
        "chrome", "firefox", "msedge", "discord", "steam", "epic",
        "nvidia", "amd", "intel", "vcredist", "directx",
        nullptr
    };

    static std::string ToLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }

    static bool IsWhitelisted(const std::string& lower) {
        for (int i = 0; k_Whitelist[i]; i++)
            if (lower.find(k_Whitelist[i]) != std::string::npos) return true;
        return false;
    }

    static bool MatchesCheatKeyword(const std::string& lower, std::string& matched) {
        for (int i = 0; k_CheatKeywords[i]; i++) {
            if (lower.find(k_CheatKeywords[i]) != std::string::npos) {
                matched = k_CheatKeywords[i];
                return true;
            }
        }
        return false;
    }

    static bool IsKnownCheatHash(const std::string& hash) {
        for (int i = 0; k_KnownCheatHashes[i]; i++)
            if (hash == k_KnownCheatHashes[i]) return true;
        return false;
    }

    static std::string QueryRegStr(HKEY hKey, const wchar_t* valueName) {
        WCHAR buf[2048] = {};
        DWORD sz = sizeof(buf);
        DWORD type = 0;
        if (RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)buf, &sz) == ERROR_SUCCESS) {
            char narrow[2048] = {};
            WideCharToMultiByte(CP_UTF8, 0, buf, -1, narrow, sizeof(narrow) - 1, NULL, NULL);
            return narrow;
        }
        return {};
    }

    // Convert Amcache LinkDate (hex FILETIME in registry) to FILETIME
    static FILETIME ParseAmcacheDate(const std::string& hexStr) {
        FILETIME ft = {};
        if (hexStr.size() >= 16) {
            ULONGLONG val = 0;
            for (int i = 0; i < 16; i++) {
                char c = hexStr[i];
                int nibble = (c >= '0' && c <= '9') ? (c - '0') :
                             (c >= 'a' && c <= 'f') ? (c - 'a' + 10) :
                             (c >= 'A' && c <= 'F') ? (c - 'A' + 10) : 0;
                val = (val << 4) | nibble;
            }
            ft.dwLowDateTime  = (DWORD)(val & 0xFFFFFFFF);
            ft.dwHighDateTime = (DWORD)(val >> 32);
        }
        return ft;
    }

    static std::string FileTimeToStr(const FILETIME& ft) {
        if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return "Unknown";
        SYSTEMTIME st = {};
        FileTimeToSystemTime(&ft, &st);
        char buf[64];
        sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d UTC",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return buf;
    }

    static double DaysSince(const FILETIME& ft) {
        FILETIME now = {};
        GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER a, b;
        a.LowPart = ft.dwLowDateTime;  a.HighPart = ft.dwHighDateTime;
        b.LowPart = now.dwLowDateTime; b.HighPart = now.dwHighDateTime;
        if (b.QuadPart < a.QuadPart) return 0.0;
        return (double)(b.QuadPart - a.QuadPart) / (10000000.0 * 86400.0);
    }

    // =========================================================================
    // Enumerate one subkey of InventoryApplicationFile
    // =========================================================================
    static void ParseAppFileEntry(HKEY hParent, const wchar_t* subkeyName,
                                   std::vector<AmcacheEntry>& out) {
        HKEY hEntry = NULL;
        if (RegOpenKeyExW(hParent, subkeyName, 0, KEY_READ, &hEntry) != ERROR_SUCCESS)
            return;

        std::string name     = QueryRegStr(hEntry, L"Name");
        std::string path     = QueryRegStr(hEntry, L"LowerCaseLongPath");
        std::string fileId   = QueryRegStr(hEntry, L"FileId");
        std::string linkDate = QueryRegStr(hEntry, L"LinkDate");

        RegCloseKey(hEntry);

        if (path.empty() && name.empty()) return;

        std::string combined = ToLower(path.empty() ? name : path);
        if (IsWhitelisted(combined)) return;

        std::string matched;
        bool isKwMatch   = MatchesCheatKeyword(combined, matched);
        bool isHashMatch = !fileId.empty() && IsKnownCheatHash(fileId);

        if (!isKwMatch && !isHashMatch) return;

        AmcacheEntry e;
        e.AppName   = name;
        e.FilePath  = path;
        e.SHA1Hash  = fileId;

        // Parse first-run date from LinkDate (stored as Unix timestamp string or FILETIME hex)
        if (!linkDate.empty()) {
            // Try as integer (Unix timestamp)
            try {
                long long ts = std::stoll(linkDate, nullptr, 16);
                if (ts > 116444736000000000LL) { // looks like FILETIME
                    e.FirstRun.dwLowDateTime  = (DWORD)(ts & 0xFFFFFFFF);
                    e.FirstRun.dwHighDateTime = (DWORD)(ts >> 32);
                } else if (ts > 0) {
                    // Unix timestamp — convert
                    LONGLONG ll = Int32x32To64(ts, 10000000) + 116444736000000000LL;
                    e.FirstRun.dwLowDateTime  = (DWORD)(ll & 0xFFFFFFFF);
                    e.FirstRun.dwHighDateTime = (DWORD)(ll >> 32);
                }
            } catch (...) {}
            e.FirstRunStr = FileTimeToStr(e.FirstRun);
        }

        e.IsCheatMatch       = isKwMatch;
        e.MatchedKeyword     = matched;
        e.IsKnownCheatHash   = isHashMatch;

        double days = DaysSince(e.FirstRun);
        e.ConfidenceScore = isHashMatch ? 95 :
                            (days < 7.0)  ? 85 :
                            (days < 30.0) ? 76 : 67;
        e.Severity = (e.ConfidenceScore >= 85) ? "CRITICAL" : "HIGH";
        e.Description = "[AMCACHE] " +
            std::string(isHashMatch ? "Known cheat hash match" : "Cheat keyword match") +
            " for \"" + (path.empty() ? name : path) + "\"" +
            (fileId.empty() ? "" : (" | SHA1: " + fileId)) +
            " | First run: " + e.FirstRunStr +
            (isKwMatch ? " | Keyword: \"" + matched + "\"" : "");

        out.push_back(e);
    }

    // =========================================================================
    // Public API
    // =========================================================================
    std::vector<AmcacheEntry> ScanAmcache() {
        std::vector<AmcacheEntry> results;

        // Load Amcache.hve as a temporary registry hive
        const wchar_t* kHivePath = L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve";
        const wchar_t* kTempKey  = L"HKLM\\ANTICHEAT_AMCACHE_TEMP";
        const wchar_t* kTempSub  = L"ANTICHEAT_AMCACHE_TEMP";

        // Enable required privilege
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            LUID luid = {};
            if (LookupPrivilegeValueW(NULL, SE_RESTORE_NAME, &luid)) {
                TOKEN_PRIVILEGES tp = {};
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
            }
            CloseHandle(hToken);
        }

        // Load the hive
        LSTATUS st = RegLoadKeyW(HKEY_LOCAL_MACHINE, kTempSub, kHivePath);
        if (st != ERROR_SUCCESS) return results; // Need admin + restore privilege

        // Open InventoryApplicationFile
        HKEY hRoot = NULL;
        st = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"ANTICHEAT_AMCACHE_TEMP\\Root\\InventoryApplicationFile",
            0, KEY_READ, &hRoot);

        if (st == ERROR_SUCCESS) {
            // Enumerate all subkeys (one per application file entry)
            DWORD idx = 0;
            WCHAR subkeyName[512] = {};
            DWORD subkeyLen = sizeof(subkeyName) / sizeof(WCHAR);

            while (RegEnumKeyExW(hRoot, idx, subkeyName, &subkeyLen,
                                  NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                ParseAppFileEntry(hRoot, subkeyName, results);
                idx++;
                subkeyLen = sizeof(subkeyName) / sizeof(WCHAR);

                if (results.size() >= 50) break; // Cap at 50 detections
            }
            RegCloseKey(hRoot);
        }

        // Unload the hive
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, kTempSub);
        return results;
    }

} // namespace AmcacheScanner
