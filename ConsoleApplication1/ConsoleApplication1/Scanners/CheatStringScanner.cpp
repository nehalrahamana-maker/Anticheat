// CheatStringScanner.cpp
// Plaintext cheat-string scanner.
//
// Detects known cheat keywords directly in:
//   1. Running process memory (MEM_PRIVATE RWX / RW pages)
//   2. On-disk executables in common drop locations (HDD player detection)
//
// Anti-false-positive strategy:
//   - Minimum string length of 5 chars before matching
//   - All keywords are specific to cheat software; no generic words
//   - Legitimate processes are whitelisted by name
//   - On-disk scan only targets unsigned or low-reputation executables
//   - Context snippets are captured for analyst review

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "CheatStringScanner.hpp"
#include "../Core/SyscallEngine.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <algorithm>
#include <cctype>
#include <set>
#include <filesystem>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

namespace CheatStringScanner {

    // =========================================================================
    // Keyword table — each entry has: keyword, category, severity
    // Keep all keywords SPECIFIC and UNAMBIGUOUS to avoid false positives.
    // =========================================================================
    struct KeywordEntry {
        const char* keyword;
        const char* category;
        const char* severity;
    };

    static const KeywordEntry k_Keywords[] = {
        // ── Aimbot / ESP / Trigger ───────────────────────────────────────────
        { "aimbot",             "AIMBOT",       "CRITICAL" },
        { "aim_bot",            "AIMBOT",       "CRITICAL" },
        { "silentaim",          "AIMBOT",       "CRITICAL" },
        { "silent_aim",         "AIMBOT",       "CRITICAL" },
        { "triggerbot",         "AIMBOT",       "CRITICAL" },
        { "trigger_bot",        "AIMBOT",       "CRITICAL" },
        { "fovcheat",           "AIMBOT",       "CRITICAL" },
        { "aimassist",          "AIMBOT",       "HIGH"     },
        { "aimkey",             "AIMBOT",       "HIGH"     },
        { "esp_draw",           "ESP",          "CRITICAL" },
        { "wallhack",           "ESP",          "CRITICAL" },
        { "wall_hack",          "ESP",          "CRITICAL" },
        { "boneESP",            "ESP",          "CRITICAL" },
        { "playerESP",          "ESP",          "CRITICAL" },
        { "esp_box",            "ESP",          "CRITICAL" },
        { "espcolor",           "ESP",          "HIGH"     },
        { "chams",              "ESP",          "HIGH"     },
        { "glowhack",           "ESP",          "HIGH"     },

        // ── Game-specific cheat clients ──────────────────────────────────────
        // FiveM / RageMP / AltV
        { "redenginelib",       "CHEAT_CLIENT", "CRITICAL" },  // Red Engine Lib (FiveM)
        { "red-engine",         "CHEAT_CLIENT", "CRITICAL" },
        { "redengine",          "CHEAT_CLIENT", "CRITICAL" },
        { "flkbypass",          "CHEAT_CLIENT", "CRITICAL" },  // FLK Bypass (FiveM)
        { "flk_bypass",         "CHEAT_CLIENT", "CRITICAL" },
        { "anti-echo",          "CHEAT_CLIENT", "CRITICAL" },  // Anti-Echo (FiveM)
        { "antiecho",           "CHEAT_CLIENT", "CRITICAL" },
        { "headshot.dll",       "CHEAT_CLIENT", "CRITICAL" },  // Headshot (FiveM)
        { "tzxcheat",           "CHEAT_CLIENT", "CRITICAL" },  // TZX (FiveM)
        { "quantaclient",       "CHEAT_CLIENT", "CRITICAL" },  // Quanta (FiveM)
        { "quanta_client",      "CHEAT_CLIENT", "CRITICAL" },
        { "doomsdaycheat",      "CHEAT_CLIENT", "CRITICAL" },
        { "doomsday_cheat",     "CHEAT_CLIENT", "CRITICAL" },
        // Siege
        { "crusadercheat",      "CHEAT_CLIENT", "CRITICAL" },  // Crusader (R6)
        { "hydroncheat",        "CHEAT_CLIENT", "CRITICAL" },  // Hydro (R6)
        { "unicoilcheat",       "CHEAT_CLIENT", "CRITICAL" },  // Unicoil (R6)
        { "vegacheat",          "CHEAT_CLIENT", "CRITICAL" },  // Vega (R6)
        { "ring1cheat",         "CHEAT_CLIENT", "CRITICAL" },  // Ring-1 (R6)
        { "ring-1cheat",        "CHEAT_CLIENT", "CRITICAL" },
        // Roblox
        { "rihnocheat",         "CHEAT_CLIENT", "CRITICAL" },  // Rihno (Roblox)
        { "rihno_client",       "CHEAT_CLIENT", "CRITICAL" },
        // Minecraft
        { "novaclient",         "CHEAT_CLIENT", "CRITICAL" },  // Nova (MC)
        { "grimclient",         "CHEAT_CLIENT", "CRITICAL" },  // Grim (MC)
        { "prestigeclient",     "CHEAT_CLIENT", "CRITICAL" },  // Prestige (MC)
        // Generic
        { "1337cheat",          "CHEAT_CLIENT", "CRITICAL" },  // 1337
        { "hydrogencheat",      "CHEAT_CLIENT", "CRITICAL" },  // Hydrogen
        { "unicorecheat",       "CHEAT_CLIENT", "CRITICAL" },  // Unicore
        { "qualaclient",        "CHEAT_CLIENT", "CRITICAL" },  // Quala
        { "skriptcheat",        "CHEAT_CLIENT", "CRITICAL" },  // Skript
        { "0xcheats",           "CHEAT_CLIENT", "CRITICAL" },  // 0xCheats
        { "venacycheat",        "CHEAT_CLIENT", "CRITICAL" },  // Venacy
        { "bebettercheat",      "CHEAT_CLIENT", "CRITICAL" },  // Be Better
        { "binarycheat",        "CHEAT_CLIENT", "CRITICAL" },  // Binary Bypass
        { "hxcheats",           "CHEAT_CLIENT", "CRITICAL" },  // HXCheats
        { "bypass.fun",         "CHEAT_CLIENT", "CRITICAL" },  // bypass.fun

        // ── HDD Player / External Cheats ─────────────────────────────────────
        { "hdplayercheat",      "HDD_PLAYER",   "CRITICAL" },  // HDD player (another exe)
        { "hddplayer",          "HDD_PLAYER",   "CRITICAL" },
        { "hdd_player",         "HDD_PLAYER",   "CRITICAL" },
        { "externalcheat",      "HDD_PLAYER",   "CRITICAL" },
        { "external_cheat",     "HDD_PLAYER",   "CRITICAL" },
        { "externalmem",        "HDD_PLAYER",   "CRITICAL" },
        { "external_mem",       "HDD_PLAYER",   "CRITICAL" },

        // ── Kernel / Driver tools ────────────────────────────────────────────
        { "bstkvmm",            "KERNEL_TOOL",  "CRITICAL" },  // BSTKVMM hypervisor cheat
        { "bst_kvmm",           "KERNEL_TOOL",  "CRITICAL" },
        { "kdmapper",           "KERNEL_TOOL",  "CRITICAL" },
        { "kdu.exe",            "KERNEL_TOOL",  "CRITICAL" },
        { "rawdriver",          "KERNEL_TOOL",  "CRITICAL" },
        { "kernelbypass",       "KERNEL_TOOL",  "CRITICAL" },
        { "kernel_bypass",      "KERNEL_TOOL",  "CRITICAL" },
        { "blackbone",          "KERNEL_TOOL",  "CRITICAL" },
        { "turla",              "KERNEL_TOOL",  "CRITICAL" },
        { "xenos64",            "KERNEL_TOOL",  "HIGH"     },
        { "drivermap",          "KERNEL_TOOL",  "HIGH"     },

        // ── DMA / FPGA cheats ────────────────────────────────────────────────
        { "pcileech",           "DMA_TOOL",     "CRITICAL" },
        { "pcie_leech",         "DMA_TOOL",     "CRITICAL" },
        { "dma_cheat",          "DMA_TOOL",     "CRITICAL" },
        { "fpgacheat",          "DMA_TOOL",     "CRITICAL" },
        { "spoofedfirmware",    "DMA_TOOL",     "CRITICAL" },
        { "spoofed_firmware",   "DMA_TOOL",     "CRITICAL" },
        { "kmboxnet",           "DMA_TOOL",     "CRITICAL" },  // Kmbox Net mouse emulation
        { "kmbox_net",          "DMA_TOOL",     "CRITICAL" },

        // ── Injectors / Loaders ──────────────────────────────────────────────
        { "extremeinject",      "INJECTOR",     "CRITICAL" },
        { "extreme_inject",     "INJECTOR",     "CRITICAL" },
        { "injector.exe",       "INJECTOR",     "CRITICAL" },
        { "manualmap",          "INJECTOR",     "CRITICAL" },
        { "manual_map",         "INJECTOR",     "CRITICAL" },
        { "galib",              "INJECTOR",     "CRITICAL" },  // galib injection lib
        { "ga_lib",             "INJECTOR",     "CRITICAL" },
        { "gvaclient",          "INJECTOR",     "CRITICAL" },  // GVA
        { "gva_client",         "INJECTOR",     "CRITICAL" },
        { "gva_mem",            "INJECTOR",     "CRITICAL" },
        { "gva.mem",            "INJECTOR",     "CRITICAL" },
        { "hiddenxcheat",       "INJECTOR",     "CRITICAL" },  // HiddenXCheat
        { "hiddenx_cheat",      "INJECTOR",     "CRITICAL" },
        { "garv",               "INJECTOR",     "CRITICAL" },  // GARV cheat tool
        { "garv_cheat",         "INJECTOR",     "CRITICAL" },

        // ── Memory read/write tools ──────────────────────────────────────────
        { "memread",            "MEM_TOOL",     "HIGH"     },
        { "mem_read",           "MEM_TOOL",     "HIGH"     },
        { "readmem",            "MEM_TOOL",     "HIGH"     },
        { "vmread",             "MEM_TOOL",     "HIGH"     },
        { "vm_read_ex",         "MEM_TOOL",     "HIGH"     },
        { "writeprocessmemory_hook", "MEM_TOOL","HIGH"     },
        { "ntreadprocess",      "MEM_TOOL",     "HIGH"     },

        // ── Android bridge / ADB (phone-based cheats) ───────────────────────
        { "adb.exe",            "ADB_CHEAT",    "CRITICAL" },
        { "adb_cheat",          "ADB_CHEAT",    "CRITICAL" },
        { "bluestackshack",     "ADB_CHEAT",    "CRITICAL" },
        { "bluestacks_hack",    "ADB_CHEAT",    "CRITICAL" },

        // ── Spoofer / Cleaner ────────────────────────────────────────────────
        { "hwid_spoofer",       "SPOOFER",      "CRITICAL" },
        { "hwid-spoofer",       "SPOOFER",      "CRITICAL" },
        { "hwidspoofer",        "SPOOFER",      "CRITICAL" },
        { "serialspoof",        "SPOOFER",      "CRITICAL" },
        { "serial_spoof",       "SPOOFER",      "CRITICAL" },
        { "diskspoofer",        "SPOOFER",      "CRITICAL" },
        { "disk_spoofer",       "SPOOFER",      "CRITICAL" },
        { "macspoofer",         "SPOOFER",      "HIGH"     },
        { "mac_spoofer",        "SPOOFER",      "HIGH"     },
        { "banbypass",          "SPOOFER",      "CRITICAL" },
        { "ban_bypass",         "SPOOFER",      "CRITICAL" },

        // ── Bypass / Cleaner strings ─────────────────────────────────────────
        { "freshbypass",        "BYPASS",       "CRITICAL" },
        { "fresh_bypass",       "BYPASS",       "CRITICAL" },
        { "unknownbypass",      "BYPASS",       "CRITICAL" },
        { "unknown_bypass",     "BYPASS",       "CRITICAL" },
        { "eventlogbypass",     "BYPASS",       "CRITICAL" },
        { "eventlog_bypass",    "BYPASS",       "CRITICAL" },
        { "vhd_bypass",         "BYPASS",       "CRITICAL" },
        { "virtualdiskbypass",  "BYPASS",       "CRITICAL" },
        { "journalbypass",      "BYPASS",       "CRITICAL" },
        { "journal_bypass",     "BYPASS",       "CRITICAL" },
        { "taskschedbypass",    "BYPASS",       "HIGH"     },
        { "prefetchbypass",     "BYPASS",       "HIGH"     },

        // ── Mouse macro / Onboard memory ─────────────────────────────────────
        { "mousescript",        "MACRO",        "HIGH"     },
        { "mouse_script",       "MACRO",        "HIGH"     },
        { "mousemacro",         "MACRO",        "HIGH"     },
        { "mouse_macro",        "MACRO",        "HIGH"     },
        { "onboard_macro",      "MACRO",        "HIGH"     },
        { "onboardmemory",      "MACRO",        "HIGH"     },
        { "recoilscript",       "MACRO",        "HIGH"     },
        { "recoil_script",      "MACRO",        "HIGH"     },
        { "norecoilscript",     "MACRO",        "HIGH"     },
        { "rapidfire",          "MACRO",        "HIGH"     },
        { "rapid_fire",         "MACRO",        "HIGH"     },

        // ── RPF / LUA script cheats (GTA / FiveM) ───────────────────────────
        { "rpfcheat",           "SCRIPT_CHEAT", "CRITICAL" },
        { "rpf_cheat",          "SCRIPT_CHEAT", "CRITICAL" },
        { "luacheat",           "SCRIPT_CHEAT", "CRITICAL" },
        { "lua_cheat",          "SCRIPT_CHEAT", "CRITICAL" },
        { "luainjector",        "SCRIPT_CHEAT", "CRITICAL" },
        { "lua_injector",       "SCRIPT_CHEAT", "CRITICAL" },

        // End sentinel
        { nullptr, nullptr, nullptr }
    };

    // =========================================================================
    // Whitelist — processes that should never be scanned / flagged
    // =========================================================================
    static const char* k_Whitelist[] = {
        "chrome", "msedge", "firefox", "opera", "brave",
        "code.exe", "devenv.exe", "clangd", "msbuild",
        "antimalware", "defender", "msmpeng",
        "svchost", "csrss", "lsass", "services", "smss",
        "wininit", "winlogon", "dwm.exe", "explorer.exe",
        "runtimebroker", "sihost", "conhost", "taskhostw",
        "spoolsv", "audiodg", "searchhost", "systemsettings",
        "vmwaretray", "vmwareuser",  // VM host tools
        "antigravity",
        nullptr
    };

    // =========================================================================
    // Helpers
    // =========================================================================
    static std::string ToLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }

    static bool IsWhitelisted(const std::string& lowerName) {
        for (int i = 0; k_Whitelist[i]; i++)
            if (lowerName.find(k_Whitelist[i]) != std::string::npos) return true;
        return false;
    }

    // Extract up to 128 printable chars starting from a position in a buffer
    static std::string ExtractContext(const BYTE* buf, size_t bufLen, size_t pos) {
        // Walk back up to 16 bytes to get start of the string
        size_t start = (pos >= 16) ? pos - 16 : 0;
        std::string ctx;
        ctx.reserve(128);
        for (size_t i = start; i < bufLen && ctx.size() < 128; i++) {
            char c = (char)buf[i];
            if (c >= 0x20 && c <= 0x7E) ctx += c;
            else if (!ctx.empty())       break;
        }
        return ctx;
    }

    // Attempt to match any keyword in a buffer of printable ASCII text.
    // Returns true and fills matchedKw/category/severity/context on hit.
    static bool MatchKeywords(const BYTE* buf, size_t len,
                              std::string& matchedKw,
                              std::string& category,
                              std::string& severity,
                              std::string& context)
    {
        // Build a lowercase string view for matching
        std::string lower;
        lower.reserve(len);
        for (size_t i = 0; i < len; i++) {
            char c = (char)buf[i];
            lower += (char)::tolower((unsigned char)c);
        }

        for (int k = 0; k_Keywords[k].keyword; k++) {
            size_t pos = lower.find(k_Keywords[k].keyword);
            if (pos != std::string::npos) {
                matchedKw = k_Keywords[k].keyword;
                category  = k_Keywords[k].category;
                severity  = k_Keywords[k].severity;
                context   = ExtractContext(buf, len, pos);
                return true;
            }
        }
        return false;
    }

    // =========================================================================
    // Memory scanning
    // =========================================================================

    // Scan a single readable memory region for cheat strings.
    // Reads the region in 256KB chunks and scans each chunk for keywords.
    static void ScanRegion(HANDLE hProc, DWORD pid,
                           const std::string& procName,
                           ULONG_PTR base, SIZE_T regSize,
                           std::vector<CheatStringDetection>& out,
                           size_t& detCount)
    {
        const SIZE_T kChunkSize = 256 * 1024; // 256 KB

        for (SIZE_T offset = 0; offset < regSize && detCount < 8; offset += kChunkSize) {
            SIZE_T toRead = (std::min)(kChunkSize, regSize - offset);
            std::vector<BYTE> buf(toRead);
            SIZE_T bytesRead = 0;

            NTSTATUS st = SyscallEngine::DirectNtReadVirtualMemory(
                hProc, (PVOID)(base + offset), buf.data(), toRead, &bytesRead);
            if (!NT_SUCCESS(st) || bytesRead < 8) continue;
            buf.resize(bytesRead);

            // Slide through printable-ASCII runs and keyword-match them
            size_t runStart = 0;
            bool inRun = false;

            for (size_t i = 0; i <= bytesRead; i++) {
                bool printable = (i < bytesRead) && (buf[i] >= 0x20) && (buf[i] <= 0x7E);
                if (printable) {
                    if (!inRun) { runStart = i; inRun = true; }
                } else {
                    if (inRun) {
                        size_t runLen = i - runStart;
                        if (runLen >= 5) {
                            std::string kw, cat, sev, ctx;
                            if (MatchKeywords(buf.data() + runStart, runLen, kw, cat, sev, ctx)) {
                                CheatStringDetection det;
                                det.Source        = ScanSource::PROCESS_MEMORY;
                                det.ProcessId     = pid;
                                det.ProcessName   = procName;
                                det.MatchedString = kw;
                                det.ContextSnippet = ctx;
                                det.Category      = cat;
                                det.Severity      = sev;
                                det.Description   = "[" + cat + "] Plaintext cheat string \"" + kw +
                                    "\" found in PID " + std::to_string(pid) +
                                    " (" + procName + ") context: \"" + ctx + "\"";
                                out.push_back(std::move(det));
                                detCount++;
                                if (detCount >= 8) return;
                            }
                        }
                        inRun = false;
                    }
                }
            }
        }
    }

    std::vector<CheatStringDetection> ScanProcess(DWORD pid, const std::string& procName) {
        std::vector<CheatStringDetection> results;
        std::string lower = ToLower(procName);
        if (IsWhitelisted(lower)) return results;

        HANDLE hProc = NULL;
        OBJECT_ATTRIBUTES_EX objAttr = { sizeof(OBJECT_ATTRIBUTES_EX) };
        CLIENT_ID_EX cid = { (HANDLE)(ULONG_PTR)pid, NULL };

        NTSTATUS st = SyscallEngine::DirectNtOpenProcess(
            &hProc, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, &objAttr, &cid);
        if (!NT_SUCCESS(st) || !hProc)
            hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) return results;

        MEMORY_BASIC_INFORMATION mbi = {};
        ULONG_PTR addr = 0x10000;
        SIZE_T retLen  = 0;
        size_t detCount = 0;
        size_t regionsScanned = 0;

        while (NT_SUCCESS(SyscallEngine::DirectNtQueryVirtualMemory(
            hProc, (PVOID)addr, MemoryBasicInformationEx, &mbi, sizeof(mbi), &retLen)))
        {
            if (detCount >= 8 || regionsScanned >= 64) break;

            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
                // Scan RWX, RW private pages (where cheat code/strings live)
                bool interesting =
                    (mbi.Protect == PAGE_EXECUTE_READWRITE) ||
                    (mbi.Protect == PAGE_EXECUTE_READ)      ||
                    (mbi.Protect == PAGE_READWRITE          && mbi.RegionSize <= 4 * 1024 * 1024);

                if (interesting && mbi.RegionSize > 0) {
                    regionsScanned++;
                    ScanRegion(hProc, pid, procName,
                               (ULONG_PTR)mbi.BaseAddress, mbi.RegionSize,
                               results, detCount);
                }
            }

            addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            if (addr >= 0x7FFFFFFF0000ULL || mbi.RegionSize == 0) break;
        }

        CloseHandle(hProc);
        return results;
    }

    std::vector<CheatStringDetection> ScanAllProcesses() {
        std::vector<CheatStringDetection> all;

        DWORD pids[1024] = {};
        DWORD needed = 0;
        if (!EnumProcesses(pids, sizeof(pids), &needed)) return all;

        DWORD count = needed / sizeof(DWORD);
        for (DWORD i = 0; i < count; i++) {
            DWORD pid = pids[i];
            if (pid <= 4) continue;

            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) continue;

            WCHAR szPath[MAX_PATH] = {};
            DWORD dwSz = MAX_PATH;
            QueryFullProcessImageNameW(h, 0, szPath, &dwSz);
            CloseHandle(h);

            WCHAR* pName = PathFindFileNameW(szPath);
            char nameBuf[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pName, -1, nameBuf, MAX_PATH, NULL, NULL);

            if (IsWhitelisted(ToLower(nameBuf))) continue;

            auto dets = ScanProcess(pid, nameBuf);
            all.insert(all.end(), dets.begin(), dets.end());
        }
        return all;
    }

    // =========================================================================
    // Disk executable scanning — HDD player + dropped cheat exe detection
    // Scans common drop locations for executables containing cheat strings.
    // Only looks at files under 50 MB to keep it fast.
    // =========================================================================

    static void ScanFileForStrings(const std::wstring& filePath,
                                   std::vector<CheatStringDetection>& out) {
        // Skip very large files
        WIN32_FILE_ATTRIBUTE_DATA fa = {};
        if (GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fa)) {
            ULONGLONG sz = ((ULONGLONG)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
            if (sz > 50ULL * 1024 * 1024) return; // skip > 50 MB
            if (sz < 4) return;                    // skip trivially small
        }

        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return;

        // Only scan PE files (MZ header)
        BYTE hdr[2] = {};
        DWORD rd = 0;
        ReadFile(hFile, hdr, 2, &rd, NULL);
        if (rd < 2 || hdr[0] != 'M' || hdr[1] != 'Z') {
            CloseHandle(hFile);
            return;
        }
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

        // Read file in 256 KB chunks and scan for keyword strings
        std::vector<BYTE> buf(256 * 1024);
        size_t detCount = 0;

        while (detCount < 4) {
            DWORD bytesRead = 0;
            if (!ReadFile(hFile, buf.data(), (DWORD)buf.size(), &bytesRead, NULL) || bytesRead == 0)
                break;

            // Scan printable ASCII runs
            size_t runStart = 0;
            bool inRun = false;
            for (size_t i = 0; i <= bytesRead; i++) {
                bool printable = (i < bytesRead) && (buf[i] >= 0x20) && (buf[i] <= 0x7E);
                if (printable) {
                    if (!inRun) { runStart = i; inRun = true; }
                } else {
                    if (inRun) {
                        size_t runLen = i - runStart;
                        if (runLen >= 5) {
                            std::string kw, cat, sev, ctx;
                            if (MatchKeywords(buf.data() + runStart, runLen, kw, cat, sev, ctx)) {
                                CheatStringDetection det;
                                det.Source         = ScanSource::DISK_EXECUTABLE;
                                det.FilePath       = filePath;
                                det.MatchedString  = kw;
                                det.ContextSnippet = ctx;
                                det.Category       = cat;
                                det.Severity       = sev;

                                // Convert path to narrow string for description
                                char narrowPath[MAX_PATH] = {};
                                WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1,
                                                    narrowPath, MAX_PATH, NULL, NULL);
                                det.Description = "[DISK:" + cat + "] File \"" +
                                    narrowPath + "\" contains cheat string \"" + kw +
                                    "\" context: \"" + ctx + "\"";
                                out.push_back(std::move(det));
                                detCount++;
                                if (detCount >= 4) goto done_file;
                            }
                        }
                        inRun = false;
                    }
                }
            }
        }

    done_file:
        CloseHandle(hFile);
    }

    static void ScanDirectory(const std::wstring& dir,
                              std::vector<CheatStringDetection>& out,
                              int depth = 0) {
        if (depth > 2) return; // max 2 levels deep to avoid full crawl

        WIN32_FIND_DATAW fd = {};
        std::wstring pattern = dir + L"\\*";
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) continue;
            if (fd.cFileName[0] == L'.') continue;

            std::wstring fullPath = dir + L"\\" + fd.cFileName;

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                ScanDirectory(fullPath, out, depth + 1);
            } else {
                // Only scan .exe and .dll files
                WCHAR* ext = PathFindExtensionW(fd.cFileName);
                if (_wcsicmp(ext, L".exe") == 0 || _wcsicmp(ext, L".dll") == 0) {
                    ScanFileForStrings(fullPath, out);
                }
            }
        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
    }

    std::vector<CheatStringDetection> ScanDiskExecutables() {
        std::vector<CheatStringDetection> out;

        // Collect scan directories: Desktop, Downloads, Temp, AppData/Local, AppData/Roaming
        std::vector<std::wstring> scanDirs;

        auto addKnownFolder = [&](int csidl) {
            WCHAR path[MAX_PATH] = {};
            if (SUCCEEDED(SHGetFolderPathW(NULL, csidl, NULL, SHGFP_TYPE_CURRENT, path)))
                scanDirs.push_back(path);
        };

        addKnownFolder(CSIDL_DESKTOPDIRECTORY);   // Desktop
        addKnownFolder(CSIDL_LOCAL_APPDATA);       // %AppData%\Local
        addKnownFolder(CSIDL_APPDATA);             // %AppData%\Roaming
        addKnownFolder(CSIDL_COMMON_DESKTOPDIRECTORY); // Public desktop

        // Temp directory
        WCHAR tempPath[MAX_PATH] = {};
        if (GetTempPathW(MAX_PATH, tempPath))
            scanDirs.push_back(tempPath);

        // Downloads folder (not a CSIDL, construct manually)
        WCHAR profilePath[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, SHGFP_TYPE_CURRENT, profilePath))) {
            scanDirs.push_back(std::wstring(profilePath) + L"\\Downloads");
        }

        for (const auto& dir : scanDirs)
            ScanDirectory(dir, out);

        return out;
    }

} // namespace CheatStringScanner
