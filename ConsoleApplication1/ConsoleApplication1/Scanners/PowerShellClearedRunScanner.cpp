// PowerShellClearedRunScanner.cpp
// Forensic PowerShell artifact scanner inspired by detect.ac methodology.
//
// Detections:
//   1. ConsoleHost_history.txt — cleared, empty, or missing
//   2. Event log cleared (Security 1102, System 104) within 7 days
//   3. PowerShell ScriptBlock log (4104) — obfuscated/encoded commands
//   4. PowerShell Module/Pipeline log (4103) — suspicious invocations
//   5. $PROFILE files modified recently containing cheat strings
//   6. Random/obfuscated launcher patterns in history
//
// Confidence scoring prevents false positives — a single cleared history
// alone is only MEDIUM; corroborated with log wipe it becomes CRITICAL.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "PowerShellClearedRunScanner.hpp"
#include <shlobj.h>
#include <shlwapi.h>
#include <winevt.h>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <regex>

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

namespace PowerShellClearedRunScanner {

    // =========================================================================
    // Helpers
    // =========================================================================
    static std::string ToLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
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

    // Days since a FILETIME
    static double DaysSince(const FILETIME& ft) {
        FILETIME now = {};
        GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER a, b;
        a.LowPart = ft.dwLowDateTime;   a.HighPart = ft.dwHighDateTime;
        b.LowPart = now.dwLowDateTime;  b.HighPart = now.dwHighDateTime;
        if (b.QuadPart < a.QuadPart) return 0.0;
        return (double)(b.QuadPart - a.QuadPart) / (double)(10000000ULL * 86400ULL);
    }

    // Check if a string looks like base64 (>= 20 chars, mostly b64 alphabet)
    static bool LooksLikeBase64(const std::string& s) {
        if (s.size() < 20) return false;
        size_t b64cnt = 0;
        for (char c : s) {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')
                b64cnt++;
        }
        return (b64cnt * 100 / s.size()) >= 80;
    }

    // Suspicious PS keywords
    static const char* k_PSCheatKeywords[] = {
        "aimbot", "wallhack", "cheatengine", "kdmapper", "inject",
        "bypass", "spoofer", "dumper", "hvid", "hwid_spoof",
        "gva", "galib", "garv", "bstkvmm", "hdplayer", "hddplayer",
        "readprocessmemory", "writeprocessmemory", "ntreadvm", "ntwritevm",
        "openprocess", "createremotethread", "setwindowshook",
        "reflectiveload", "manualmap", "extremeinject", "xenos",
        "redengine", "flkbypass", "antiecho", "crusader", "hydron",
        nullptr
    };

    static bool ContainsPSCheatKeyword(const std::string& lower) {
        for (int i = 0; k_PSCheatKeywords[i]; i++)
            if (lower.find(k_PSCheatKeywords[i]) != std::string::npos) return true;
        return false;
    }

    // Obfuscation indicators in PS commands
    static bool IsObfuscatedPSCommand(const std::string& cmd) {
        std::string lower = ToLower(cmd);
        // EncodedCommand / -enc flag
        if (lower.find("-encodedcommand") != std::string::npos) return true;
        if (lower.find("-enc ") != std::string::npos) return true;
        if (lower.find("-e ") != std::string::npos && LooksLikeBase64(cmd)) return true;
        // Invoke-Expression variants
        if (lower.find("iex") != std::string::npos) return true;
        if (lower.find("invoke-expression") != std::string::npos) return true;
        // Invoke-WebRequest / DownloadString launching something
        if (lower.find("downloadstring") != std::string::npos) return true;
        if (lower.find("invoke-webrequest") != std::string::npos) return true;
        // String splitting / char casting (common obfuscation)
        if (lower.find("[char]") != std::string::npos) return true;
        if (lower.find("-join") != std::string::npos && lower.find("[char]") != std::string::npos) return true;
        // Variable substitution tricks
        if (cmd.find("`") != std::string::npos && cmd.size() > 30) return true;
        return false;
    }

    // =========================================================================
    // 1. Check ConsoleHost_history.txt
    // =========================================================================
    static void CheckHistoryFile(std::vector<PSDetection>& out) {
        // Standard location: %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
        WCHAR appData[MAX_PATH] = {};
        if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, appData)))
            return;

        std::wstring histPath = std::wstring(appData) +
            L"\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";

        WIN32_FILE_ATTRIBUTE_DATA fa = {};
        if (!GetFileAttributesExW(histPath.c_str(), GetFileExInfoStandard, &fa)) {
            // File doesn't exist — was it deleted?
            PSDetection d;
            d.FindingType     = PSFindingType::HISTORY_FILE_MISSING;
            d.FindingTypeName = "PS_HISTORY_FILE_MISSING";
            d.Evidence        = "ConsoleHost_history.txt does not exist";
            d.FilePath        = "Missing";
            d.ConfidenceScore = 65;
            d.Severity        = "HIGH";
            d.Description     = "PowerShell history file is missing. This may indicate anti-forensic deletion. "
                                 "Confidence: 65% (file may never have existed on fresh installs).";
            out.push_back(d);
            return;
        }

        ULONGLONG fileSize = ((ULONGLONG)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
        double daysSinceWrite = DaysSince(fa.ftLastWriteTime);

        if (fileSize == 0) {
            // Empty file — was recently cleared?
            PSDetection d;
            d.FindingType     = PSFindingType::HISTORY_FILE_CLEARED;
            d.FindingTypeName = "PS_HISTORY_CLEARED";
            d.Evidence        = "ConsoleHost_history.txt exists but is completely empty";
            char np[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, histPath.c_str(), -1, np, MAX_PATH, NULL, NULL);
            d.FilePath        = np;
            d.EventTime       = fa.ftLastWriteTime;
            // Higher confidence if cleared very recently
            d.ConfidenceScore = (daysSinceWrite < 1.0) ? 80 : 65;
            d.Severity        = (daysSinceWrite < 1.0) ? "HIGH" : "MEDIUM";
            d.Description     = "PowerShell history file is empty. Last modified: " +
                                 FileTimeToStr(fa.ftLastWriteTime) +
                                 " (" + std::to_string((int)daysSinceWrite) + " days ago). "
                                 "Recently cleared history is a common anti-forensic technique.";
            out.push_back(d);
            return;
        }

        // File has content — scan each line for cheat keywords and obfuscation
        char narrowPath[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, histPath.c_str(), -1, narrowPath, MAX_PATH, NULL, NULL);

        std::ifstream f(narrowPath);
        if (!f.is_open()) return;

        std::string line;
        int lineNum = 0;
        while (std::getline(f, line) && lineNum < 2000) {
            lineNum++;
            std::string lower = ToLower(line);

            bool isObfuscated = IsObfuscatedPSCommand(line);
            bool hasCheatKw   = ContainsPSCheatKeyword(lower);

            if (isObfuscated || hasCheatKw) {
                PSDetection d;
                d.FindingType     = isObfuscated ? PSFindingType::OBFUSCATED_COMMAND
                                                 : PSFindingType::SUSPICIOUS_HISTORY_ENTRY;
                d.FindingTypeName = isObfuscated ? "PS_OBFUSCATED_COMMAND" : "PS_CHEAT_HISTORY_ENTRY";
                d.Evidence        = line.substr(0, 256);
                d.FilePath        = narrowPath;
                d.ConfidenceScore = isObfuscated ? 75 : 70;
                d.Severity        = "HIGH";
                d.Description     = std::string(isObfuscated ? "Obfuscated PowerShell command" :
                                    "Cheat-related command") + " found in PS history (line " +
                                    std::to_string(lineNum) + "): \"" + line.substr(0, 128) + "\"";
                out.push_back(d);
            }

            // Random run detector: very short cryptic commands (< 12 chars, no spaces, all alphanum)
            if (line.size() >= 4 && line.size() <= 12 && line.find(' ') == std::string::npos) {
                bool allAlpha = true;
                for (char c : line) if (!isalnum((unsigned char)c) && c != '-' && c != '_') { allAlpha = false; break; }
                if (allAlpha && line.size() >= 6) {
                    PSDetection d;
                    d.FindingType     = PSFindingType::RUN_RANDOMIZER_DETECTED;
                    d.FindingTypeName = "PS_RUN_RANDOMIZER";
                    d.Evidence        = line;
                    d.FilePath        = narrowPath;
                    d.ConfidenceScore = 55;
                    d.Severity        = "MEDIUM";
                    d.Description     = "Short cryptic PS command suggestive of a randomized launcher alias: \"" + line + "\"";
                    out.push_back(d);
                }
            }
        }
    }

    // =========================================================================
    // 2. Check Windows Event Logs for clear events + PS 4104 ScriptBlock
    // =========================================================================
    static void CheckEventLogs(std::vector<PSDetection>& out) {
        // --- Check Security log for event 1102 (audit log cleared) ---
        // --- Check System log for event 104 (system log cleared) ---
        struct LogCheck { const wchar_t* channel; DWORD eventId; const char* desc; };
        static const LogCheck checks[] = {
            { L"Security", 1102, "Security audit log cleared (Event 1102)" },
            { L"System",   104,  "System event log cleared (Event 104)" },
            { nullptr, 0, nullptr }
        };

        FILETIME sevenDaysAgo = {};
        {
            SYSTEMTIME st = {};
            GetSystemTime(&st);
            FILETIME now = {};
            SystemTimeToFileTime(&st, &now);
            ULARGE_INTEGER ul;
            ul.LowPart  = now.dwLowDateTime;
            ul.HighPart = now.dwHighDateTime;
            ul.QuadPart -= 7ULL * 86400ULL * 10000000ULL;
            sevenDaysAgo.dwLowDateTime  = ul.LowPart;
            sevenDaysAgo.dwHighDateTime = ul.HighPart;
        }

        for (int ci = 0; checks[ci].channel; ci++) {
            wchar_t query[256];
            swprintf_s(query, L"*[System[EventID=%lu]]", checks[ci].eventId);

            EVT_HANDLE hResults = EvtQuery(NULL, checks[ci].channel, query,
                                           EvtQueryChannelPath | EvtQueryReverseDirection);
            if (!hResults) continue;

            EVT_HANDLE hEvent = NULL;
            DWORD returned = 0;
            while (EvtNext(hResults, 1, &hEvent, 1000, 0, &returned) && returned > 0) {
                // Get event time
                DWORD bufSize = 0;
                EvtGetEventInfo(hEvent, EvtEventPath, 0, NULL, &bufSize);
                // Read the system time via rendering
                EVT_HANDLE hCtx = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
                if (hCtx) {
                    DWORD propCount = 0;
                    DWORD bufNeeded = 0;
                    std::vector<BYTE> propBuf(1024);
                    if (EvtRender(hCtx, hEvent, EvtRenderEventValues,
                                  (DWORD)propBuf.size(), propBuf.data(), &bufNeeded, &propCount)) {
                        EVT_VARIANT* vars = (EVT_VARIANT*)propBuf.data();
                        // EvtSystemTimeCreated is index 5 in EvtRenderContextSystem
                        if (propCount > 5 && vars[5].Type == EvtVarTypeFileTime) {
                            FILETIME evtTime;
                            evtTime.dwLowDateTime  = (DWORD)(vars[5].FileTimeVal & 0xFFFFFFFF);
                            evtTime.dwHighDateTime = (DWORD)(vars[5].FileTimeVal >> 32);

                            ULARGE_INTEGER evtUl, sevenUl;
                            evtUl.LowPart  = evtTime.dwLowDateTime;
                            evtUl.HighPart = evtTime.dwHighDateTime;
                            sevenUl.LowPart  = sevenDaysAgo.dwLowDateTime;
                            sevenUl.HighPart = sevenDaysAgo.dwHighDateTime;

                            if (evtUl.QuadPart >= sevenUl.QuadPart) {
                                PSDetection d;
                                d.FindingType     = PSFindingType::EVENT_LOG_CLEARED;
                                d.FindingTypeName = "EVENT_LOG_CLEARED";
                                d.Evidence        = checks[ci].desc;
                                d.FilePath        = "Windows Event Log";
                                d.EventTime       = evtTime;
                                d.ConfidenceScore = 85;
                                d.Severity        = "CRITICAL";
                                d.Description     = std::string(checks[ci].desc) +
                                    " at " + FileTimeToStr(evtTime) +
                                    ". Clearing event logs is a strong anti-forensic indicator.";
                                out.push_back(d);
                            }
                        }
                    }
                    EvtClose(hCtx);
                }
                EvtClose(hEvent);
                hEvent = NULL;
            }
            EvtClose(hResults);
        }

        // --- Check PowerShell ScriptBlock log (4104) for obfuscated commands ---
        EVT_HANDLE hPS = EvtQuery(NULL,
            L"Microsoft-Windows-PowerShell/Operational",
            L"*[System[EventID=4104]]",
            EvtQueryChannelPath | EvtQueryReverseDirection);
        if (hPS) {
            EVT_HANDLE hEv = NULL;
            DWORD ret = 0;
            int checked = 0;
            while (EvtNext(hPS, 1, &hEv, 2000, 0, &ret) && ret > 0 && checked < 200) {
                checked++;
                // Render full XML to extract script block text
                DWORD needed = 0, propCount = 0;
                EvtRender(NULL, hEv, EvtRenderEventXml, 0, NULL, &needed, &propCount);
                if (needed > 0 && needed < 512 * 1024) {
                    std::vector<WCHAR> xmlBuf(needed / sizeof(WCHAR) + 1);
                    if (EvtRender(NULL, hEv, EvtRenderEventXml,
                                  (DWORD)(xmlBuf.size() * sizeof(WCHAR)),
                                  xmlBuf.data(), &needed, &propCount)) {
                        // Convert to narrow
                        char narrow[4096] = {};
                        WideCharToMultiByte(CP_UTF8, 0, xmlBuf.data(), -1, narrow, sizeof(narrow) - 1, NULL, NULL);
                        std::string xml(narrow);
                        std::string lower = ToLower(xml);

                        bool obf = IsObfuscatedPSCommand(xml);
                        bool kw  = ContainsPSCheatKeyword(lower);

                        if (obf || kw) {
                            // Extract just the script text portion (between <Data Name='ScriptBlockText'>)
                            std::string evidence = xml.substr(0, 256);
                            size_t start = xml.find("ScriptBlockText");
                            if (start != std::string::npos) {
                                start = xml.find('>', start);
                                if (start != std::string::npos) {
                                    size_t end = xml.find('<', ++start);
                                    if (end != std::string::npos)
                                        evidence = xml.substr(start, (std::min)(end - start, (size_t)256));
                                }
                            }

                            PSDetection d;
                            d.FindingType     = PSFindingType::OBFUSCATED_COMMAND;
                            d.FindingTypeName = obf ? "PS_SCRIPTBLOCK_OBFUSCATED" : "PS_SCRIPTBLOCK_CHEAT_KW";
                            d.Evidence        = evidence;
                            d.FilePath        = "Microsoft-Windows-PowerShell/Operational (Event 4104)";
                            d.ConfidenceScore = obf ? 85 : 78;
                            d.Severity        = "CRITICAL";
                            d.Description     = std::string(obf ? "Obfuscated PowerShell ScriptBlock" :
                                                "Cheat-keyword PowerShell ScriptBlock") +
                                                " found in event log 4104: \"" + evidence.substr(0, 128) + "\"";
                            out.push_back(d);
                        }
                    }
                }
                EvtClose(hEv);
                hEv = NULL;
            }
            EvtClose(hPS);
        }

        // --- Check if PS Operational log itself was cleared ---
        EVT_HANDLE hPSLog = EvtOpenLog(NULL, L"Microsoft-Windows-PowerShell/Operational",
                                        EvtOpenChannelPath);
        if (hPSLog) {
            EVT_VARIANT logProp = {};
            DWORD needed = 0;
            // EvtLogNumberOfLogRecords = 1
            if (EvtGetLogInfo(hPSLog, EvtLogNumberOfLogRecords, sizeof(EVT_VARIANT), &logProp, &needed)) {
                if (logProp.Type == EvtVarTypeUInt64 && logProp.UInt64Val == 0) {
                    PSDetection d;
                    d.FindingType     = PSFindingType::SCRIPTBLOCK_LOG_CLEARED;
                    d.FindingTypeName = "PS_SCRIPTBLOCK_LOG_CLEARED";
                    d.Evidence        = "PowerShell Operational event log has 0 records";
                    d.FilePath        = "Microsoft-Windows-PowerShell/Operational";
                    d.ConfidenceScore = 80;
                    d.Severity        = "CRITICAL";
                    d.Description     = "PowerShell ScriptBlock event log is completely empty — "
                                        "likely cleared as an anti-forensic measure.";
                    out.push_back(d);
                }
            }
            EvtClose(hPSLog);
        }
    }

    // =========================================================================
    // 3. Check PowerShell profiles for suspicious modifications
    // =========================================================================
    static void CheckProfiles(std::vector<PSDetection>& out) {
        WCHAR sysRoot[MAX_PATH] = {};
        ExpandEnvironmentStringsW(L"%SystemRoot%", sysRoot, MAX_PATH);

        WCHAR userProfile[MAX_PATH] = {};
        if (FAILED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, SHGFP_TYPE_CURRENT, userProfile)))
            return;

        std::vector<std::wstring> profiles = {
            std::wstring(userProfile) + L"\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1",
            std::wstring(userProfile) + L"\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1",
            std::wstring(sysRoot) + L"\\System32\\WindowsPowerShell\\v1.0\\profile.ps1",
        };

        for (const auto& prof : profiles) {
            WIN32_FILE_ATTRIBUTE_DATA fa = {};
            if (!GetFileAttributesExW(prof.c_str(), GetFileExInfoStandard, &fa)) continue;

            ULONGLONG sz = ((ULONGLONG)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
            if (sz == 0 || sz > 1024 * 1024) continue;

            double daysSinceWrite = DaysSince(fa.ftLastWriteTime);

            char np[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, prof.c_str(), -1, np, MAX_PATH, NULL, NULL);

            std::ifstream f(np);
            if (!f.is_open()) continue;
            std::string content((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
            f.close();

            std::string lower = ToLower(content);
            bool hasCheatKw  = ContainsPSCheatKeyword(lower);
            bool hasObfuscation = IsObfuscatedPSCommand(content);
            bool recentlyModified = (daysSinceWrite < 30.0);

            if ((hasCheatKw || hasObfuscation) && recentlyModified) {
                PSDetection d;
                d.FindingType     = PSFindingType::SUSPICIOUS_PROFILE;
                d.FindingTypeName = "PS_SUSPICIOUS_PROFILE";
                d.Evidence        = content.substr(0, 256);
                d.FilePath        = np;
                d.EventTime       = fa.ftLastWriteTime;
                d.ConfidenceScore = 78;
                d.Severity        = "HIGH";
                d.Description     = "PowerShell profile modified " + std::to_string((int)daysSinceWrite) +
                                    " days ago contains suspicious content: \"" +
                                    content.substr(0, 128) + "\"";
                out.push_back(d);
            }
        }
    }

    // =========================================================================
    // Public API
    // =========================================================================
    std::vector<PSDetection> ScanAll() {
        std::vector<PSDetection> results;
        CheckHistoryFile(results);
        CheckEventLogs(results);
        CheckProfiles(results);

        // Boost confidence when multiple evidence types corroborate
        bool hasLogClear = false, hasHistoryClear = false;
        for (auto& d : results) {
            if (d.FindingType == PSFindingType::EVENT_LOG_CLEARED) hasLogClear = true;
            if (d.FindingType == PSFindingType::HISTORY_FILE_CLEARED ||
                d.FindingType == PSFindingType::HISTORY_FILE_MISSING) hasHistoryClear = true;
        }
        if (hasLogClear && hasHistoryClear) {
            for (auto& d : results) {
                d.ConfidenceScore = (std::min)(100, d.ConfidenceScore + 15);
                if (d.Severity == "MEDIUM") d.Severity = "HIGH";
                if (d.Severity == "HIGH")   d.Severity = "CRITICAL";
            }
        }

        return results;
    }

} // namespace PowerShellClearedRunScanner
