// ShimcacheScanner.cpp
// Reads the Windows AppCompatCache (Shimcache) from the registry.
// The Shimcache records every executable that has been run or
// present on the system — entries persist until the cache is
// flushed (typically on shutdown/reboot, up to 1024 entries kept).
//
// Registry path:
//   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache
//
// Win10/11 binary format (each entry):
//   Offset 0x00 — Cache entry size (DWORD)
//   Offset 0x08 — Path offset (DWORD) into the data blob
//   Offset 0x0C — Path length (WORD)
//   Offset 0x10 — Last modified time (FILETIME)
//   ... followed by the path string (UTF-16)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "ShimcacheScanner.hpp"
#include <algorithm>
#include <string>

namespace ShimcacheScanner {

    static const char* k_CheatKeywords[] = {
        "aimbot", "wallhack", "cheat", "inject", "hack", "bypass",
        "spoofer", "loader", "triggerbot", "silentaim", "norecoil",
        "hdplayer", "hddplayer", "gva", "galib", "garv", "bstkvmm",
        "xenos", "kdmapper", "redengine", "flkbypass", "antiecho",
        "crusader", "hydron", "vegacheat", "ring1cheat", "hxcheats",
        "binarycheat", "venacy", "externhack", "manualmap",
        "doomsday", "finalexp", "novaclient", "grimclient",
        nullptr
    };

    static const char* k_Whitelist[] = {
        "\\windows\\", "\\program files\\", "\\program files (x86)\\",
        "\\syswow64\\", "\\system32\\", "\\winsxs\\", "\\driverstore\\",
        nullptr
    };

    static std::string ToLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }

    static std::string WStrToStr(const WCHAR* w, int len) {
        if (!w || len <= 0) return {};
        char buf[2048] = {};
        WideCharToMultiByte(CP_UTF8, 0, w, len / (int)sizeof(WCHAR), buf, sizeof(buf) - 1, NULL, NULL);
        return buf;
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
    // Parse AppCompatCache binary blob (Win10/11)
    // The blob starts with a 128-byte header (signature "10ts" or similar)
    // followed by variable-length entries.
    // =========================================================================
    static void ParseWin10ShimCache(const std::vector<BYTE>& data,
                                     std::vector<ShimcacheEntry>& out) {
        const size_t len = data.size();
        if (len < 0x30) return;

        // Win10 signature: first 4 bytes = 0x30 (entry count follows at 0x04)
        // Actual entry data starts at offset 0x80 (128)
        const size_t kHeaderSize = 0x80;
        if (len <= kHeaderSize) return;

        const BYTE* p   = data.data() + kHeaderSize;
        const BYTE* end = data.data() + len;

        while (p + 0x20 <= end) {
            // Each entry starts with a DWORD data size
            DWORD dataOff   = 0;
            DWORD dataLen   = 0;
            FILETIME modTime = {};

            // Try to read path offset and length
            // Win10 layout at each entry:
            //   +0x00 DWORD : Signature / control (0x73617473 = "sats")
            //   +0x04 DWORD : unknown
            //   +0x08 DWORD : data size
            //   +0x0C ...
            // The path is embedded as a counted Unicode string

            // Simple scan: look for UTF-16 backslash sequences (path prefix)
            // Walk 4 bytes at a time looking for a WORD path length followed by a path
            WORD pathLen = 0;
            DWORD pathOff = 0;

            // Try reading path length at various known offsets
            for (DWORD tryOff = 0; tryOff <= 0x30 && p + tryOff + 4 <= end; tryOff += 4) {
                WORD candidate = *(WORD*)(p + tryOff);
                // Sane path length: 8..800 bytes (4..400 wide chars)
                if (candidate >= 8 && candidate <= 800 && (candidate & 1) == 0) {
                    DWORD strDataOff = tryOff + 4;
                    if (p + strDataOff + candidate <= end) {
                        // Check that the data starts with a drive letter (L"C:\") or UNC
                        const WCHAR* wstr = (const WCHAR*)(p + strDataOff);
                        int nChars = candidate / 2;
                        if (nChars >= 4 && wstr[1] == L':' && wstr[2] == L'\\') {
                            pathLen = candidate;
                            pathOff = strDataOff;
                            // Try to read FILETIME following the string
                            DWORD afterStr = pathOff + pathLen;
                            if (p + afterStr + 8 <= end) {
                                modTime = *(FILETIME*)(p + afterStr);
                            }
                            break;
                        }
                    }
                }
            }

            if (pathLen > 0 && pathOff + pathLen <= (DWORD)(end - p)) {
                std::wstring wpath((const WCHAR*)(p + pathOff), pathLen / 2);
                std::string narrow = WStrToStr(wpath.c_str(), pathLen);
                std::string lower  = ToLower(narrow);

                if (!IsWhitelisted(lower)) {
                    std::string matched;
                    if (MatchesCheatKeyword(lower, matched)) {
                        ShimcacheEntry se;
                        se.FilePath       = wpath;
                        se.FilePathNarrow = narrow;
                        se.LastModified   = modTime;
                        se.LastModifiedStr = FileTimeToStr(modTime);
                        se.IsCheatMatch   = true;
                        se.MatchedKeyword = matched;

                        double days = DaysSince(modTime);
                        se.ConfidenceScore = (days < 1.0) ? 88 :
                                             (days < 7.0) ? 80 :
                                             (days < 30.0) ? 72 : 63;
                        se.Severity = (se.ConfidenceScore >= 80) ? "CRITICAL" : "HIGH";
                        se.Description = "[SHIMCACHE] Cheat executable in AppCompatCache: \"" +
                            narrow + "\". Last file modified: " + se.LastModifiedStr +
                            ". Keyword: \"" + matched + "\".";
                        out.push_back(se);
                    }
                }
                // Advance past this entry (minimum step to avoid infinite loop)
                p += pathOff + pathLen + 8;
            } else {
                p += 4; // advance 4 bytes if we can't parse
            }

            if (p >= end) break;
        }
    }

    // =========================================================================
    // Public API
    // =========================================================================
    std::vector<ShimcacheEntry> ScanShimcache() {
        std::vector<ShimcacheEntry> results;

        HKEY hKey = NULL;
        LSTATUS st = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
            0, KEY_READ, &hKey);
        if (st != ERROR_SUCCESS) return results;

        DWORD dataSize = 0;
        RegQueryValueExW(hKey, L"AppCompatCache", NULL, NULL, NULL, &dataSize);
        if (dataSize == 0 || dataSize > 16 * 1024 * 1024) {
            RegCloseKey(hKey);
            return results;
        }

        std::vector<BYTE> data(dataSize);
        DWORD type = 0;
        st = RegQueryValueExW(hKey, L"AppCompatCache", NULL, &type, data.data(), &dataSize);
        RegCloseKey(hKey);

        if (st != ERROR_SUCCESS) return results;

        ParseWin10ShimCache(data, results);
        return results;
    }

} // namespace ShimcacheScanner
