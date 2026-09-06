// DLLProxyScanner.cpp
// Comprehensive DLL Proxy, Sideloading, and Search-Order Hijack Scanner
// Detects:
//   1. Search-Order Hijacking / System DLL Shadowing across ALL System32/SysWOW64 modules.
//   2. Export-Forwarding Shims (DLLs that forward exports to proxy/intercept API calls).
//   3. Suspicious Path Injections (DLLs loaded from Temp, AppData, Downloads, Desktop, ProgramData).
//   4. Unsigned / Non-Microsoft DLLs loaded into target game/emulator processes.

#include "DLLProxyScanner.hpp"
#include "SigScanner.hpp"
#include "PEParser.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <algorithm>
#include <set>
#include <fstream>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

namespace DLLProxyScanner {

    // ------------------------------------------------------------------ helpers

    static std::string ToLower(const std::string& s) {
        std::string r = s;
        std::transform(r.begin(), r.end(), r.begin(), ::tolower);
        return r;
    }

    static std::string WideToNarrow(const std::wstring& ws) {
        if (ws.empty()) return {};
        char buf[MAX_PATH * 2] = {};
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, buf, sizeof(buf), NULL, NULL);
        return buf;
    }

    // Returns the canonical System32 or SysWOW64 path for a module by name,
    // or empty string if not a known system DLL.
    static std::string GetExpectedSystemPath(const std::string& moduleNameLower) {
        char sys32[MAX_PATH] = {};
        GetSystemDirectoryA(sys32, MAX_PATH);
        char syswow[MAX_PATH] = {};
        ExpandEnvironmentStringsA("%SystemRoot%\\SysWOW64", syswow, MAX_PATH);

        std::string sys32Path = std::string(sys32) + "\\" + moduleNameLower;
        std::string syswowPath = std::string(syswow) + "\\" + moduleNameLower;

        if (GetFileAttributesA(sys32Path.c_str()) != INVALID_FILE_ATTRIBUTES)
            return sys32Path;
        if (GetFileAttributesA(syswowPath.c_str()) != INVALID_FILE_ATTRIBUTES)
            return syswowPath;

        return {};
    }

    struct ExportInfo {
        DWORD total      = 0;
        DWORD forwarded  = 0;
        std::string forwardTarget;
    };

    static ExportInfo ParseExports(const std::vector<BYTE>& rawBuffer) {
        ExportInfo info;
        if (rawBuffer.size() < sizeof(IMAGE_DOS_HEADER)) return info;

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawBuffer.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return info;
        if ((size_t)dos->e_lfanew + sizeof(DWORD) > rawBuffer.size()) return info;

        DWORD sig = *reinterpret_cast<const DWORD*>(rawBuffer.data() + dos->e_lfanew);
        if (sig != IMAGE_NT_SIGNATURE) return info;

        auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(
            rawBuffer.data() + dos->e_lfanew + sizeof(DWORD));
        size_t optOff = (size_t)dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (optOff >= rawBuffer.size()) return info;

        WORD magic = *reinterpret_cast<const WORD*>(rawBuffer.data() + optOff);
        DWORD exportRVA = 0, exportSzRVA = 0;

        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(rawBuffer.data() + optOff);
            if (opt->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                exportRVA   = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                exportSzRVA = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
        } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(rawBuffer.data() + optOff);
            if (opt->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                exportRVA   = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                exportSzRVA = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
        }
        if (!exportRVA) return info;

        auto* secs = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            rawBuffer.data() + optOff + fh->SizeOfOptionalHeader);
        auto rva2off = [&](DWORD rva) -> DWORD {
            for (WORD i = 0; i < fh->NumberOfSections; i++) {
                if (rva >= secs[i].VirtualAddress &&
                    rva < secs[i].VirtualAddress + secs[i].Misc.VirtualSize) {
                    return secs[i].PointerToRawData + (rva - secs[i].VirtualAddress);
                }
            }
            return 0;
        };

        DWORD expOff = rva2off(exportRVA);
        if (!expOff || expOff + sizeof(IMAGE_EXPORT_DIRECTORY) > rawBuffer.size()) return info;

        auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(rawBuffer.data() + expOff);
        info.total = exp->NumberOfFunctions;

        DWORD funcsOff = rva2off(exp->AddressOfFunctions);
        if (!funcsOff) return info;

        DWORD exportEnd = exportRVA + exportSzRVA;

        for (DWORD i = 0; i < exp->NumberOfFunctions; i++) {
            size_t fOff = (size_t)funcsOff + i * sizeof(DWORD);
            if (fOff + sizeof(DWORD) > rawBuffer.size()) break;
            DWORD funcRVA = *reinterpret_cast<const DWORD*>(rawBuffer.data() + fOff);
            if (!funcRVA) continue;

            if (funcRVA >= exportRVA && funcRVA < exportEnd) {
                info.forwarded++;
                if (info.forwardTarget.empty()) {
                    DWORD fwdOff = rva2off(funcRVA);
                    if (fwdOff && fwdOff < rawBuffer.size()) {
                        const char* fwdStr = reinterpret_cast<const char*>(rawBuffer.data() + fwdOff);
                        std::string fs(fwdStr, strnlen(fwdStr, 128));
                        size_t dot = fs.find('.');
                        if (dot != std::string::npos) {
                            info.forwardTarget = ToLower(fs.substr(0, dot)) + ".dll";
                        }
                    }
                }
            }
        }
        return info;
    }

    static bool IsLegitimateOverridePath(const std::string& lowerPath) {
        return lowerPath.find("\\winsxs\\")      != std::string::npos ||
               lowerPath.find("\\driverstore\\") != std::string::npos ||
               lowerPath.find("\\system32\\")    != std::string::npos ||
               lowerPath.find("\\syswow64\\")    != std::string::npos ||
               lowerPath.find("\\microsoft.net\\") != std::string::npos;
    }

    static bool IsSuspiciousStagingPath(const std::string& lowerPath) {
        return lowerPath.find("\\temp\\") != std::string::npos ||
               lowerPath.find("\\appdata\\") != std::string::npos ||
               lowerPath.find("\\downloads\\") != std::string::npos ||
               lowerPath.find("\\desktop\\") != std::string::npos ||
               lowerPath.find("\\programdata\\") != std::string::npos ||
               lowerPath.find("c:\\temp") != std::string::npos;
    }

    static bool IsWhitelistedSystemProcess(const std::string& lowerName) {
        static const char* wl[] = {
            "chrome", "msedge", "firefox", "opera", "brave",
            "code.exe", "devenv.exe", "msbuild", "antigravity",
            "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
            "smss.exe", "wininit.exe", "winlogon.exe", "dwm.exe",
            "explorer.exe", "runtimebroker.exe", "sihost.exe", nullptr
        };
        for (int i = 0; wl[i]; i++) {
            if (lowerName.find(wl[i]) != std::string::npos) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ per-process scan

    std::vector<DLLProxyDetection> ScanProcessDLLProxy(DWORD pid, const std::string& procName) {
        std::vector<DLLProxyDetection> detections;

        std::string lowerProc = ToLower(procName);
        if (IsWhitelistedSystemProcess(lowerProc)) return detections;

        std::string appDir;
        {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProc) {
                WCHAR exePath[MAX_PATH] = {};
                DWORD sz = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, exePath, &sz)) {
                    WCHAR* lastSlash = wcsrchr(exePath, L'\\');
                    if (lastSlash) *lastSlash = L'\0';
                    appDir = ToLower(WideToNarrow(exePath));
                }
                CloseHandle(hProc);
            }
        }

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnap == INVALID_HANDLE_VALUE) return detections;

        MODULEENTRY32W me = {};
        me.dwSize = sizeof(me);

        if (!Module32FirstW(hSnap, &me)) {
            CloseHandle(hSnap);
            return detections;
        }

        std::set<std::string> seenModules;

        do {
            char modNameBuf[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, modNameBuf, MAX_PATH, NULL, NULL);
            std::string modName = modNameBuf;
            std::string modNameLower = ToLower(modName);

            char modPathBuf[MAX_PATH * 2] = {};
            WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, modPathBuf, sizeof(modPathBuf), NULL, NULL);
            std::string loadedPath = modPathBuf;
            std::string loadedPathLower = ToLower(loadedPath);

            if (seenModules.count(loadedPathLower)) {
                me.dwSize = sizeof(me);
                continue;
            }
            seenModules.insert(loadedPathLower);

            // Skip primary executable binary itself
            if (loadedPathLower.rfind(".exe") == loadedPathLower.size() - 4) {
                me.dwSize = sizeof(me);
                continue;
            }

            // 1. Check if it's shadowing a canonical system DLL
            std::string expectedSysPath = GetExpectedSystemPath(modNameLower);
            bool isSystemShadow = false;
            if (!expectedSysPath.empty()) {
                std::string expectedLower = ToLower(expectedSysPath);
                if (loadedPathLower != expectedLower && !IsLegitimateOverridePath(loadedPathLower)) {
                    isSystemShadow = true;
                }
            }

            // 2. Check if loaded from a suspicious staging path (Temp, AppData, Downloads, Desktop)
            bool isSuspiciousLocation = IsSuspiciousStagingPath(loadedPathLower);

            // 3. Check if loaded directly from the application folder (and not inside System32)
            bool isAppLocalDLL = (!appDir.empty() && loadedPathLower.rfind(appDir, 0) == 0 && !IsLegitimateOverridePath(loadedPathLower));

            // If none of these conditions are met and it's inside Windows/System32, it's normal
            if (!isSystemShadow && !isSuspiciousLocation && !isAppLocalDLL) {
                me.dwSize = sizeof(me);
                continue;
            }

            // Parse PE header & export forwarding table of suspect DLL
            PE::PEImage loadedPE;
            WCHAR wLoaded[MAX_PATH * 2] = {};
            MultiByteToWideChar(CP_UTF8, 0, loadedPath.c_str(), -1, wLoaded, sizeof(wLoaded) / sizeof(WCHAR));

            bool peLoaded = loadedPE.LoadFromFile(wLoaded);
            ExportInfo loadedExp;
            std::string sha256 = "";
            bool isSigned = false, isMsSigned = false;
            std::string signer = "";

            if (peLoaded) {
                loadedExp = ParseExports(loadedPE.GetRawBuffer());
                sha256 = PE::PEImage::ComputeSHA256(loadedPE.GetRawBuffer());
                auto cert = loadedPE.ParseCertificate(wLoaded);
                isSigned = cert.HasCertificate && cert.IsTrusted;
                isMsSigned = cert.IsMicrosoftSigned;
                signer = cert.SubjectName;
            }

            // If it's legitimate Microsoft signed and in a standard Windows path, skip
            if (isMsSigned && IsLegitimateOverridePath(loadedPathLower)) {
                me.dwSize = sizeof(me);
                continue;
            }

            // Detect Proxy / Hijack Indicators:
            bool isThreat = false;
            std::string technique = "";
            std::string severity = "HIGH";
            std::string desc = "";

            // A. Export Forwarding Shim (Classic Proxy DLL pattern)
            if (loadedExp.forwarded > 0 || !loadedExp.forwardTarget.empty()) {
                isThreat = true;
                technique = "EXPORT_FORWARD_PROXY_SHIM";
                severity = "CRITICAL";
                desc = "Proxy DLL wrapper detected: '" + modName + "' loaded from '" + loadedPath +
                       "' forwards " + std::to_string(loadedExp.forwarded) + " export(s) to '" +
                       loadedExp.forwardTarget + "'. Intercepts API calls to execute cheat payloads.";
            }
            // B. System DLL Search-Order Hijacking
            else if (isSystemShadow) {
                isThreat = true;
                technique = "SEARCH_ORDER_HIJACK";
                severity = "CRITICAL";
                desc = "System DLL search-order hijack: '" + modName + "' loaded from '" + loadedPath +
                       "' instead of canonical path '" + expectedSysPath + "'. Sideloaded DLL injection.";
            }
            // C. Suspicious Staging Path Injection
            else if (isSuspiciousLocation && !isMsSigned) {
                isThreat = true;
                technique = "SUSPICIOUS_PATH_INJECTION";
                severity = "CRITICAL";
                desc = "Untrusted/unsigned DLL loaded from staging path: '" + loadedPath +
                       "' in PID " + std::to_string(pid) + " (" + procName + ").";
            }
            // D. Unsigned App-Local Proxy DLL
            else if (isAppLocalDLL && !isMsSigned && (!isSigned || loadedExp.total > 0)) {
                // If it has exports or is unsigned, flag as app-local sideload proxy
                isThreat = true;
                technique = "APP_LOCAL_DLL_SIDELOAD";
                severity = isSigned ? "HIGH" : "CRITICAL";
                desc = "Application-local sideloaded DLL: '" + modName + "' loaded from '" + loadedPath +
                       "'. Unverified/custom module placed next to executable.";
            }

            if (isThreat) {
                DLLProxyDetection det;
                det.ProcessId               = pid;
                det.ProcessName             = procName;
                det.LoadedPath              = loadedPath;
                det.ExpectedSystemPath      = expectedSysPath;
                det.IsPathHijacked          = isSystemShadow;
                det.HasForwardedExports     = (loadedExp.forwarded > 0);
                det.ForwardTargetDll        = loadedExp.forwardTarget;
                det.LoadedExportCount       = loadedExp.total;
                det.ForwardedExportCount    = loadedExp.forwarded;
                det.LoadedSHA256            = sha256;
                det.LoadedIsSigned          = isSigned;
                det.LoadedIsMicrosoftSigned = isMsSigned;
                det.LoadedSignerSubject     = signer;
                det.ProxyTechnique          = technique;
                det.Severity                = severity;
                det.Description             = desc;

                detections.push_back(det);
            }

            me.dwSize = sizeof(me);
        } while (Module32NextW(hSnap, &me));

        CloseHandle(hSnap);
        return detections;
    }

    // ------------------------------------------------------------------ all processes scan

    std::vector<DLLProxyDetection> ScanAllProcessesDLLProxy() {
        std::vector<DLLProxyDetection> all;

        DWORD pids[2048] = {};
        DWORD needed = 0;
        if (!EnumProcesses(pids, sizeof(pids), &needed)) return all;

        DWORD count = needed / sizeof(DWORD);
        for (DWORD i = 0; i < count; i++) {
            DWORD pid = pids[i];
            if (pid <= 4) continue;

            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) continue;

            WCHAR szName[MAX_PATH] = {};
            DWORD dwSz = MAX_PATH;
            QueryFullProcessImageNameW(h, 0, szName, &dwSz);
            CloseHandle(h);

            WCHAR* pName = PathFindFileNameW(szName);
            char nameBuf[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pName, -1, nameBuf, MAX_PATH, NULL, NULL);

            std::string lowerName = ToLower(nameBuf);
            if (IsWhitelistedSystemProcess(lowerName)) continue;

            auto dets = ScanProcessDLLProxy(pid, nameBuf);
            if (!dets.empty()) {
                all.insert(all.end(), dets.begin(), dets.end());
            }
        }

        return all;
    }

} // namespace DLLProxyScanner
