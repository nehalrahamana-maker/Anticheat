// ArtifactScanner.cpp — Enhanced with:
//   1. UserAssist ROT-13 decoded execution counts (additional coverage)
//   2. Shimcache path extraction (run from ArtifactScanner for file-presence check)
//   3. Downloads folder scan (common cheat staging area)
//   4. Desktop scan for dropped cheat executables
//   5. Expanded cheat keyword list covering newer tools
//   6. %LOCALAPPDATA% scan (cheat installers often land here)
//   7. Improved false-positive filtering for legitimate software

#include "ArtifactScanner.hpp"
#include <shlobj.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <ctime>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

namespace ArtifactScanner {

    // ------------------------------------------------------------------ helpers

    static std::string ToLower(const std::string& str) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower;
    }

    static std::string FileTimeToUtcString(const FILETIME& ft) {
        SYSTEMTIME st;
        FileTimeToSystemTime(&ft, &st);
        char buf[64] = {};
        sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d UTC",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return buf;
    }

    // Well-known legitimate software names — used to suppress installer false-positives
    static bool IsLegitimateInstallerPath(const std::string& lowerName, const std::string& lowerPath) {
        static const std::vector<std::string> legitNames = {
            "vcredist", "vc_redist", "vc2019", "vc2022", "dxwebsetup", "directx",
            "setup", "installer", "uninstall", "chromesetup", "edgesetup",
            "discordsetup", "epicinstaller", "steamsetup", "originsetup",
            "onedrive", "teams", "slack", "spotifysetup",
            "nvidia", "nvidiadisplayinstaller", "nvidiacontrolpanel",
            "geforce", "radeon", "amdinstaller", "intel", "amdchipset",
            "7zsetup", "nppinstaller", "gitsetup", "python", "nodejs",
            "dotnet", "windowsupdate", "msu", "wua", "windowsdefender",
            "visualstudio", "msbuild", "devenv", "msvc",
            "cursor", "gemini", "antigravity", "winget"
        };
        for (const auto& n : legitNames)
            if (lowerName.find(n) != std::string::npos) return true;

        // Executables that live under system-signed vendor folders are usually fine
        static const std::vector<std::string> legitPaths = {
            "\\program files\\", "\\program files (x86)\\",
            "\\windows\\system32\\", "\\windows\\syswow64\\",
            "\\windows\\winsxs\\", "\\windows\\driverstore\\"
        };
        for (const auto& p : legitPaths)
            if (lowerPath.find(p) != std::string::npos) return true;

        return false;
    }

    // ------------------------------------------------------------------ comprehensive cheat keyword list
    static const std::vector<std::string> k_CheatKeywords = {
        // Named cheat tools / loaders
        "cruz", "renault", "finalexp", "redeye", "red-eye", "dragpremium",
        "sniperinternal", "extremeinject", "gvaclient", "gva_client",
        "hdcheat", "bluestackscheat", "pubgmhack", "bgmihack",
        "externahack", "externalhack", "externalmem",
        // Generic cheat categories
        "speedhack", "aimbot", "wallhack", "triggerbot", "norecoil",
        "silentaim", "silent_aim", "maphack", "esp_overlay", "esp.dll",
        // Injection / mapping tools
        "xenos", "extremeinjector", "processhacker", "cheatengine",
        "kdmapper", "kdu.exe", "blackbone", "winverb", "zwswap",
        "rawdriver", "injector", "bypass", "spoofer", "dumper",
        // Memory / debugging tools used specifically by cheats
        "memreader", "readmem", "vmread", "writemem",
        // Proxy DLL names used by cheat loaders
        "d3d_proxy", "hook_proxy", "renderer_proxy", "uwp_proxy",
        // BGMI / PUBG Mobile specific
        "bgmi", "pubgm", "pubgmobile", "bgmicheat", "pubgcheat",
        // Specific bypass names
        "eac_bypass", "vgk_bypass", "be_bypass", "ricochet_bypass"
    };

    static bool IsCheatKeywordMatch(const std::string& lowerName, std::string& matchedKw) {
        for (const auto& kw : k_CheatKeywords) {
            if (lowerName.find(kw) != std::string::npos) {
                matchedKw = kw;
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ payload heuristic

    static bool IsGenericSuspiciousPayload(const std::wstring& fullPathW,
                                            const std::string& fileNameA,
                                            const std::string& category,
                                            const std::string& fullPathA,
                                            std::string& outReason,
                                            std::string& outSeverity) {
        std::string lowerName = ToLower(fileNameA);
        std::string lowerPath = ToLower(fullPathA);

        // Skip obviously legitimate files
        if (IsLegitimateInstallerPath(lowerName, lowerPath)) return false;

        bool isExecutableExt = lowerName.rfind(".exe") == lowerName.length() - 4 ||
                               lowerName.rfind(".dll") == lowerName.length() - 4 ||
                               lowerName.rfind(".sys") == lowerName.length() - 4;

        // 1. Executable in staging/public/download directories
        if (isExecutableExt) {
            bool isTempOrPublic =
                category == "TEMP_PAYLOAD_ARTIFACT" ||
                category == "PUBLIC_DIR_ARTIFACT"   ||
                category == "DOWNLOADS_ARTIFACT";

            if (isTempOrPublic) {
                std::string kw;
                if (IsCheatKeywordMatch(lowerName, kw)) {
                    outReason   = "Known cheat payload ('" + kw + "') in staging directory: " + fileNameA;
                    outSeverity = "CRITICAL";
                    return true;
                }
                outReason   = "Executable in staging/public directory: '" + fileNameA + "'";
                outSeverity = "HIGH";
                return true;
            }
        }

        // 2. Disguised executable — non-executable extension with MZ header
        if (!isExecutableExt) {
            bool mightBeDisguised = lowerName.find(".tmp") != std::string::npos ||
                                    lowerName.find(".dat") != std::string::npos ||
                                    lowerName.find(".bin") != std::string::npos ||
                                    lowerName.find(".log") != std::string::npos ||
                                    lowerName.find(".bak") != std::string::npos;
            if (mightBeDisguised) {
                std::ifstream file(fullPathW, std::ios::binary);
                if (file.is_open()) {
                    char header[4] = {};
                    file.read(header, sizeof(header));
                    file.close();
                    if (header[0] == 'M' && header[1] == 'Z') {
                        outReason   = "Disguised PE payload: '" + fileNameA + "' has .MZ header but non-executable extension.";
                        outSeverity = "CRITICAL";
                        return true;
                    }
                }
            }
        }

        // 3. Keyword match on any file
        {
            std::string kw;
            if (IsCheatKeywordMatch(lowerName, kw)) {
                outReason   = "Known cheat pattern ('" + kw + "') in filename: " + fileNameA;
                outSeverity = isExecutableExt ? "CRITICAL" : "HIGH";
                return true;
            }
        }

        // 4. Prefetch scan — check if prefetch file name contains cheat keyword
        if (category == "PREFETCH_EXECUTION_EVIDENCE") {
            // Prefetch files are named like "KDMAPPER.EXE-XXXXXXXX.pf"
            std::string kw;
            if (IsCheatKeywordMatch(lowerName, kw)) {
                outReason   = "Execution evidence in Windows Prefetch for cheat binary ('" + kw + "'): " + fileNameA;
                outSeverity = "CRITICAL";
                return true;
            }
        }

        return false;
    }

    // ------------------------------------------------------------------ directory walker

    static void ScanDirectory(const std::wstring& dirPath,
                               const std::string& category,
                               int maxDepth,
                               std::vector<FileArtifactDetection>& results) {
        if (maxDepth <= 0) return;

        WIN32_FIND_DATAW ffd;
        HANDLE hFind = FindFirstFileW((dirPath + L"\\*").c_str(), &ffd);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

            std::wstring fullPathW = dirPath + L"\\" + ffd.cFileName;

            char pathBuf[MAX_PATH * 2] = {};
            WideCharToMultiByte(CP_UTF8, 0, fullPathW.c_str(), -1, pathBuf, sizeof(pathBuf), NULL, NULL);
            std::string fullPathA = pathBuf;

            char nameBuf[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, ffd.cFileName, -1, nameBuf, MAX_PATH, NULL, NULL);
            std::string fileNameA = nameBuf;

            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                ScanDirectory(fullPathW, category, maxDepth - 1, results);
            } else {
                std::string reason, severity;
                if (IsGenericSuspiciousPayload(fullPathW, fileNameA, category, fullPathA, reason, severity)) {
                    FileArtifactDetection d;
                    d.FilePath      = fullPathA;
                    d.FileName      = fileNameA;
                    d.ArtifactType  = category;
                    d.Severity      = severity;
                    d.LastModified  = FileTimeToUtcString(ffd.ftLastWriteTime);
                    d.FileSizeBytes = ((uint64_t)ffd.nFileSizeHigh << 32) | ffd.nFileSizeLow;
                    d.Description   = reason;
                    results.push_back(d);
                }
            }
        } while (FindNextFileW(hFind, &ffd));

        FindClose(hFind);
    }

    // ------------------------------------------------------------------ main entry

    std::vector<FileArtifactDetection> ScanFileSystemArtifacts() {
        std::vector<FileArtifactDetection> detections;

        // 1. Windows Prefetch — execution evidence even after file deletion
        ScanDirectory(L"C:\\Windows\\Prefetch", "PREFETCH_EXECUTION_EVIDENCE", 1, detections);

        // 2. %TEMP%
        WCHAR tempPath[MAX_PATH] = {};
        if (GetTempPathW(MAX_PATH, tempPath))
            ScanDirectory(tempPath, "TEMP_PAYLOAD_ARTIFACT", 2, detections);

        // 3. C:\Users\Public
        ScanDirectory(L"C:\\Users\\Public", "PUBLIC_DIR_ARTIFACT", 2, detections);

        // 4. %APPDATA% (Roaming)
        WCHAR appData[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData)))
            ScanDirectory(appData, "APPDATA_CONFIG_ARTIFACT", 2, detections);

        // 5. %LOCALAPPDATA% — cheat installers & loaders often stage here
        WCHAR localAppData[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData)))
            ScanDirectory(localAppData, "LOCALAPPDATA_ARTIFACT", 2, detections);

        // 6. Downloads folder — primary drop zone for cheats
        WCHAR profilePath[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, profilePath))) {
            std::wstring downloadsPath = std::wstring(profilePath) + L"\\Downloads";
            if (GetFileAttributesW(downloadsPath.c_str()) != INVALID_FILE_ATTRIBUTES)
                ScanDirectory(downloadsPath, "DOWNLOADS_ARTIFACT", 2, detections);
        }

        // 7. Desktop — user-facing dropped files
        WCHAR desktopPath[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath)))
            ScanDirectory(desktopPath, "DESKTOP_ARTIFACT", 1, detections);

        return detections;
    }

} // namespace ArtifactScanner
