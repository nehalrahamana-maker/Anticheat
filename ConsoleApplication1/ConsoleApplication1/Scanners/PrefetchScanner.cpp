// PrefetchScanner.cpp
// Parses Windows Prefetch (.pf) files in C:\Windows\Prefetch\
// to detect historical evidence of cheat executable runs.
//
// Prefetch files are created by the Windows Superfetch service
// each time an executable runs. They persist even after the exe
// is deleted — making them powerful forensic artifacts.
//
// SCCA format parsing (Win10/11 Format 30):
//   Offset 0x00 — Version (DWORD)
//   Offset 0x04 — Signature "SCCA" (DWORD)
//   Offset 0x0C — File size (DWORD)
//   Offset 0x10 — Executable name (UTF-16, 60 WCHARs)
//   Offset 0x4C — Prefetch hash (DWORD)
//   Metrics / run count / timestamps follow format-specific offsets.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "PrefetchScanner.hpp"
#include <shlwapi.h>
#include <algorithm>
#include <fstream>
#include <string>

#pragma comment(lib, "shlwapi.lib")

namespace PrefetchScanner {

    // Cheat-related keywords to match against executable names
    static const char* k_CheatKeywords[] = {
        "aimbot", "wallhack", "cheat", "inject", "hack", "bypass",
        "spoofer", "dumper", "loader", "trainer", "triggerbot",
        "silentaim", "esp", "norecoil", "hdplayer", "hddplayer",
        "gva", "galib", "garv", "bstkvmm", "xenos", "kdmapper",
        "redengine", "flkbypass", "antiecho", "crusader", "hydron",
        "vegacheat", "ring1", "hxcheats", "binarycheat", "venacy",
        "externalmem", "externhack", "manualmap", "reflectiv",
        "doomsday", "finalexp", "skriptcheat", "novaclient",
        nullptr
    };

    // Legitimate false-positive names to ignore
    static const char* k_Whitelist[] = {
        "chrome", "firefox", "msedge", "discord", "steam", "epic",
        "spotify", "vlc", "notepad", "explorer", "taskmgr",
        "devenv", "msbuild", "code", "powershell", "cmd",
        "winrar", "7z", nullptr
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

    static std::string FileTimeToStr(const FILETIME& ft) {
        if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return "Unknown";
        SYSTEMTIME st = {};
        FileTimeToSystemTime(&ft, &st);
        char buf[64];
        sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d UTC",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return buf;
    }

    // Convert 100ns FILETIME intervals (ULONGLONG) stored in prefetch to FILETIME
    static FILETIME ULLToFILETIME(ULONGLONG ull) {
        FILETIME ft;
        ft.dwLowDateTime  = (DWORD)(ull & 0xFFFFFFFF);
        ft.dwHighDateTime = (DWORD)(ull >> 32);
        return ft;
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
    // Parse a single .pf file
    // =========================================================================
    static bool ParsePrefetchFile(const std::wstring& pfPath, PrefetchEntry& entry) {
        HANDLE hFile = CreateFileW(pfPath.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        // Read header (at least 0x5C bytes)
        BYTE hdr[0x100] = {};
        DWORD rd = 0;
        ReadFile(hFile, hdr, sizeof(hdr), &rd, NULL);
        CloseHandle(hFile);

        if (rd < 0x5C) return false;

        // Signature check: "SCCA" at offset 4
        if (hdr[4] != 'S' || hdr[5] != 'C' || hdr[6] != 'C' || hdr[7] != 'A') return false;

        DWORD version = *(DWORD*)(hdr + 0x00);
        // Supported: 17 (XP), 23 (Win7), 26 (Win8), 30 (Win10/11)
        if (version != 30 && version != 26 && version != 23 && version != 17) return false;

        // Executable name at offset 0x10, UTF-16, max 60 WCHARs
        WCHAR exeNameW[64] = {};
        memcpy(exeNameW, hdr + 0x10, sizeof(WCHAR) * 60);
        exeNameW[60] = 0;

        char exeNameA[128] = {};
        WideCharToMultiByte(CP_UTF8, 0, exeNameW, -1, exeNameA, sizeof(exeNameA) - 1, NULL, NULL);
        entry.ExeName = exeNameA;

        // File size at 0x0C
        // DWORD fileSize = *(DWORD*)(hdr + 0x0C);

        // For Win10 (version 30), run count is at offset 0xD0,
        // last run timestamps are 8 x ULONGLONG starting at 0x80
        if (version == 30 && rd >= 0xD4) {
            BYTE extHdr[0x200] = {};
            HANDLE hFile2 = CreateFileW(pfPath.c_str(), GENERIC_READ,
                                        FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile2 != INVALID_HANDLE_VALUE) {
                DWORD rd2 = 0;
                ReadFile(hFile2, extHdr, sizeof(extHdr), &rd2, NULL);
                CloseHandle(hFile2);
                if (rd2 >= 0xD4) {
                    entry.RunCount = *(DWORD*)(extHdr + 0xD0);
                    // Last run timestamp is the first of 8 at 0x80
                    ULONGLONG lastRunUll = *(ULONGLONG*)(extHdr + 0x80);
                    if (lastRunUll > 0) {
                        entry.LastRun    = ULLToFILETIME(lastRunUll);
                        entry.LastRunStr = FileTimeToStr(entry.LastRun);
                    }
                }
            }
        }

        entry.PfFilePath = pfPath;
        return true;
    }

    // =========================================================================
    // Public API
    // =========================================================================
    std::vector<PrefetchEntry> ScanPrefetch() {
        std::vector<PrefetchEntry> results;

        WCHAR prefetchDir[MAX_PATH] = {};
        ExpandEnvironmentStringsW(L"%SystemRoot%\\Prefetch", prefetchDir, MAX_PATH);

        std::wstring pattern = std::wstring(prefetchDir) + L"\\*.pf";
        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) return results;

        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            std::wstring fullPath = std::wstring(prefetchDir) + L"\\" + fd.cFileName;
            PrefetchEntry entry;
            if (!ParsePrefetchFile(fullPath, entry)) continue;

            std::string lower = ToLower(entry.ExeName);
            if (IsWhitelisted(lower)) continue;

            std::string matched;
            if (MatchesCheatKeyword(lower, matched)) {
                entry.IsCheatMatch  = true;
                entry.MatchedKeyword = matched;

                // Higher confidence if run recently
                double days = (entry.LastRun.dwLowDateTime || entry.LastRun.dwHighDateTime)
                              ? DaysSince(entry.LastRun) : 9999.0;

                entry.ConfidenceScore = (days < 1.0) ? 90 :
                                        (days < 7.0) ? 82 :
                                        (days < 30.0) ? 74 : 65;
                entry.Severity = (entry.ConfidenceScore >= 82) ? "CRITICAL" : "HIGH";
                entry.Description = "[PREFETCH] Cheat executable \"" + entry.ExeName +
                    "\" was run " + std::to_string(entry.RunCount) + " time(s). " +
                    "Last run: " + (entry.LastRunStr.empty() ? "Unknown" : entry.LastRunStr) +
                    ". Matched keyword: \"" + matched + "\".";

                results.push_back(entry);
            }
        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
        return results;
    }

} // namespace PrefetchScanner
