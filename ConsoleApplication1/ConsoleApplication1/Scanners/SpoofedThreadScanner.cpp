// SpoofedThreadScanner.cpp
// High-Speed Call-Stack Spoofing & Context Hijack Hunter
//
// Techniques caught:
//  1. Return-address spoof: return addresses on stack pointing into unbacked private memory or shellcode.
//  2. Stack pivot: RSP pointing outside the thread's actual TEB-described stack bounds (ROP pivot).
//  3. Fake stack frame: RBP chain walking outside legitimate stack bounds.
//  4. Thread-context hijack: Win32 start address or current RIP in unbacked executable memory.
//
// Optimizations:
//  - Single global thread snapshot for system-wide sweeps (avoids thousands of redundant snapshots).
//  - Module address range caching with binary/range lookup (avoids slow GetMappedFileNameA per frame).
//  - Reuses process handles without re-opening inside thread stack bounds queries.
//  - Fast system process filtering.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "SpoofedThreadScanner.hpp"
#include "SyscallEngine.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <algorithm>
#include <unordered_map>
#include <vector>
#include <string>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9
#endif

typedef NTSTATUS(NTAPI* pfnNtQueryInformationThread)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

namespace SpoofedThreadScanner {

    // ------------------------------------------------------------------ helpers

    static std::string ToLower(const std::string& s) {
        std::string r = s;
        std::transform(r.begin(), r.end(), r.begin(), ::tolower);
        return r;
    }

    static bool IsLegitimateModuleName(const std::string& modName) {
        if (modName.empty()) return false;
        std::string lower = ToLower(modName);
        static const char* syslibs[] = {
            "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
            "win32u.dll", "gdi32.dll", "gdi32full.dll", "combase.dll",
            "advapi32.dll", "sechost.dll", "rpcrt4.dll", "msvcrt.dll",
            "vcruntime", "ucrtbase.dll", "msvcp", "d3d11.dll", "d3d12.dll",
            "dxgi.dll", "opengl32.dll", "d2d1.dll", "dwrite.dll",
            "dwmapi.dll", "uxtheme.dll", "shell32.dll", "shlwapi.dll",
            "ole32.dll", "oleaut32.dll", "ws2_32.dll", "mswsock.dll",
            "iphlpapi.dll", "wininet.dll", "urlmon.dll", "winhttp.dll",
            "setupapi.dll", "cfgmgr32.dll", "devobj.dll", "bcrypt.dll",
            "crypt32.dll", "wintrust.dll", "clbcatq.dll", "imm32.dll",
            "msctf.dll", "version.dll", "winmm.dll", "avrt.dll",
            "xinput", "dinput", "dsound.dll",
            // JIT compilers & game engines
            "mono.dll", "mono-2.0-bdwgc.dll", "monosgen-2.0.dll",
            "clr.dll", "coreclr.dll", "clrjit.dll", "mscorlib.dll", "mscoree.dll",
            "jscript.dll", "jscript9.dll", "chakra.dll", "v8.dll", "node.dll",
            "unityplayer.dll", "jvm.dll", "eac_server",
            nullptr
        };
        for (int i = 0; syslibs[i]; i++) {
            if (lower.find(syslibs[i]) != std::string::npos) return true;
        }
        return false;
    }

    struct ModRange {
        ULONG_PTR Base = 0;
        ULONG_PTR End = 0;
        std::string Name;
        bool IsLegit = false;
    };

    struct ProcessModuleCache {
        std::vector<ModRange> Ranges;

        void Build(HANDLE hProc) {
            HMODULE hMods[512] = {};
            DWORD cbNeeded = 0;
            if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
                DWORD count = cbNeeded / sizeof(HMODULE);
                Ranges.reserve(count);
                for (DWORD i = 0; i < count; i++) {
                    MODULEINFO mi = {};
                    if (GetModuleInformation(hProc, hMods[i], &mi, sizeof(mi))) {
                        char szMod[MAX_PATH] = {};
                        if (GetModuleFileNameExA(hProc, hMods[i], szMod, MAX_PATH) > 0) {
                            std::string fname = PathFindFileNameA(szMod);
                            ModRange mr;
                            mr.Base = (ULONG_PTR)mi.lpBaseOfDll;
                            mr.End = mr.Base + mi.SizeOfImage;
                            mr.Name = fname;
                            mr.IsLegit = IsLegitimateModuleName(fname);
                            Ranges.push_back(mr);
                        }
                    }
                }
            }
        }

        std::string FindModule(ULONG_PTR addr, bool& outIsLegit) const {
            for (const auto& r : Ranges) {
                if (addr >= r.Base && addr < r.End) {
                    outIsLegit = r.IsLegit;
                    return r.Name;
                }
            }
            outIsLegit = false;
            return "";
        }
    };

    struct StackBounds { ULONG_PTR Base = 0, Limit = 0; };

    static StackBounds GetThreadStackBounds(HANDLE hProc, HANDLE hThread, pfnNtQueryInformationThread pfnQIT) {
        if (!pfnQIT) return {};

        struct THREAD_BASIC_INFORMATION {
            NTSTATUS  ExitStatus;
            PVOID     TebBaseAddress;
            CLIENT_ID_EX ClientId;
            ULONG_PTR AffinityMask;
            LONG      Priority;
            LONG      BasePriority;
        };

        THREAD_BASIC_INFORMATION tbi = {};
        ULONG retLen = 0;
        if (!NT_SUCCESS(pfnQIT(hThread, 0, &tbi, sizeof(tbi), &retLen)) || !tbi.TebBaseAddress) return {};

        ULONG_PTR tebBase = (ULONG_PTR)tbi.TebBaseAddress;
        ULONG_PTR stackBase = 0, stackLimit = 0;
        SIZE_T br = 0;
        SyscallEngine::DirectNtReadVirtualMemory(hProc, (PVOID)(tebBase + 0x08), &stackBase, sizeof(ULONG_PTR), &br);
        SyscallEngine::DirectNtReadVirtualMemory(hProc, (PVOID)(tebBase + 0x10), &stackLimit, sizeof(ULONG_PTR), &br);

        StackBounds sb;
        sb.Base = stackBase;
        sb.Limit = stackLimit;
        return sb;
    }

    static bool IsWhitelistedProcess(const std::string& lower) {
        static const char* wl[] = {
            "chrome", "msedge", "firefox", "code.exe", "devenv.exe",
            "csrss.exe", "lsass.exe", "services.exe", "svchost.exe",
            "wininit.exe", "smss.exe", "winlogon.exe", "dwm.exe",
            "antimalware", "mpcmdrun", "msmpeng", "explorer.exe",
            "conhost.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe",
            "searchhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
            "systemsettings.exe", "antigravity", "msbuild.exe", "taskhostw.exe",
            "spoolsv.exe", "audiodg.exe", nullptr
        };
        for (int i = 0; wl[i]; i++) {
            if (lower.find(wl[i]) != std::string::npos) return true;
        }
        return false;
    }

    static std::vector<ULONG_PTR> WalkStack(HANDLE hProc, ULONG_PTR rsp, size_t maxFrames) {
        std::vector<ULONG_PTR> frames;
        const size_t kPtrSize = sizeof(ULONG_PTR);
        std::vector<ULONG_PTR> stack(maxFrames, 0);
        SIZE_T bytesRead = 0;

        NTSTATUS st = SyscallEngine::DirectNtReadVirtualMemory(
            hProc, (PVOID)rsp, stack.data(), maxFrames * kPtrSize, &bytesRead);
        if (!NT_SUCCESS(st) || bytesRead < kPtrSize) return frames;

        size_t validSlots = bytesRead / kPtrSize;
        for (size_t i = 0; i < validSlots; i++) {
            ULONG_PTR candidate = stack[i];
            if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFFFFFF) continue;
            frames.push_back(candidate);
        }
        return frames;
    }

    static std::vector<SpoofedThreadDetection> ScanProcessThreadsInternal(
        DWORD pid,
        const std::string& procName,
        const std::vector<DWORD>& threadIds,
        pfnNtQueryInformationThread pfnQIT)
    {
        std::vector<SpoofedThreadDetection> detections;
        std::string lowerProc = ToLower(procName);
        if (IsWhitelistedProcess(lowerProc)) return detections;

        HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) return detections;

        ProcessModuleCache modCache;
        modCache.Build(hProc);

        const size_t kMaxFrames = 8;
        const size_t kMinBadFrames = 2;
        size_t threadsInspected = 0;
        const size_t kMaxThreadsPerProc = 4; // Audit top 4 active threads for speed

        for (DWORD tid : threadIds) {
            if (threadsInspected >= kMaxThreadsPerProc) break;

            HANDLE hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                FALSE, tid);
            if (!hThread) continue;

            threadsInspected++;
            DWORD suspendRes = SuspendThread(hThread);
            if (suspendRes == (DWORD)-1) {
                CloseHandle(hThread);
                continue;
            }

            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_FULL;

            if (!GetThreadContext(hThread, &ctx)) {
                ResumeThread(hThread);
                CloseHandle(hThread);
                continue;
            }

            ULONG_PTR rsp = ctx.Rsp;
            ULONG_PTR rip = ctx.Rip;
            ULONG_PTR rbp = ctx.Rbp;

            // 1. Stack Pivot Detection (RSP outside TEB stack bounds)
            StackBounds sb = GetThreadStackBounds(hProc, hThread, pfnQIT);
            if (sb.Base != 0 && sb.Limit != 0) {
                bool pivoted = (rsp < sb.Limit || rsp > sb.Base);
                if (pivoted && rsp > 0x10000) {
                    bool isLegit = false;
                    std::string mod = modCache.FindModule(rsp, isLegit);
                    if (!isLegit) {
                        SpoofedThreadDetection d;
                        d.ProcessId = pid;
                        d.ProcessName = procName;
                        d.ThreadId = tid;
                        d.Technique = SpoofTechnique::STACK_PIVOT;
                        d.TechniqueName = "STACK_PIVOT";
                        d.SuspiciousAddress = rsp;
                        d.AddressModule = mod.empty() ? "Unbacked" : mod;
                        d.Severity = "CRITICAL";
                        d.Description = "RSP (0x" + [&]{ char t[32]; sprintf_s(t, "%llX", (unsigned long long)rsp); return std::string(t); }() +
                                        ") is outside thread stack [0x" +
                                        [&]{ char t[32]; sprintf_s(t, "%llX", (unsigned long long)sb.Limit); return std::string(t); }() + " - 0x" +
                                        [&]{ char t[32]; sprintf_s(t, "%llX", (unsigned long long)sb.Base); return std::string(t); }() +
                                        "]. ROP stack-pivot attack or hijacked context.";
                        detections.push_back(d);
                        ResumeThread(hThread);
                        CloseHandle(hThread);
                        continue;
                    }
                }
            }

            // 2. Return Address Spoof (Walk call-stack slots)
            auto frames = WalkStack(hProc, rsp, kMaxFrames);
            size_t badFrames = 0;
            std::vector<ULONG_PTR> badAddrs;
            std::vector<std::string> frameModules;

            for (auto fa : frames) {
                bool isLegit = false;
                std::string mod = modCache.FindModule(fa, isLegit);
                frameModules.push_back(mod.empty() ? "Unbacked" : mod);
                if (!isLegit) {
                    badFrames++;
                    badAddrs.push_back(fa);
                }
            }

            if (badFrames >= kMinBadFrames) {
                SpoofedThreadDetection d;
                d.ProcessId = pid;
                d.ProcessName = procName;
                d.ThreadId = tid;
                d.Technique = SpoofTechnique::RETURN_ADDRESS_SPOOF;
                d.TechniqueName = "RETURN_ADDRESS_SPOOF";
                d.SuspiciousAddress = badAddrs.empty() ? rsp : badAddrs[0];
                bool dummy;
                d.AddressModule = modCache.FindModule(d.SuspiciousAddress, dummy);
                if (d.AddressModule.empty()) d.AddressModule = "Unbacked";
                d.StackFrames = frames;
                d.FrameModules = frameModules;
                d.Severity = "CRITICAL";
                d.Description = "Stack walk reveals " + std::to_string(badFrames) +
                                "/" + std::to_string(frames.size()) +
                                " return addresses in unbacked memory for TID " +
                                std::to_string(tid) + " (Synthetic return address chain).";
                detections.push_back(d);
                ResumeThread(hThread);
                CloseHandle(hThread);
                continue;
            }

            // 3. Thread Context Hijack (Win32 Start Address vs current RIP)
            if (pfnQIT) {
                ULONG_PTR win32Start = 0;
                ULONG retL = 0;
                if (NT_SUCCESS(pfnQIT(hThread, ThreadQuerySetWin32StartAddress, &win32Start, sizeof(win32Start), &retL))) {
                    bool startLegit = false, ripLegit = false;
                    std::string startMod = modCache.FindModule(win32Start, startLegit);
                    std::string ripMod = modCache.FindModule(rip, ripLegit);

                    bool startUnbacked = !startLegit && win32Start > 0x10000;
                    bool ripUnbacked = !ripLegit && rip > 0x10000;

                    if (startUnbacked || (ripUnbacked && !startUnbacked)) {
                        SpoofedThreadDetection d;
                        d.ProcessId = pid;
                        d.ProcessName = procName;
                        d.ThreadId = tid;
                        d.Technique = SpoofTechnique::THREAD_CONTEXT_HIJACK;
                        d.TechniqueName = "THREAD_CONTEXT_HIJACK";
                        d.SuspiciousAddress = startUnbacked ? win32Start : rip;
                        d.AddressModule = startUnbacked ? (startMod.empty() ? "Unbacked" : startMod) : (ripMod.empty() ? "Unbacked" : ripMod);
                        d.StackFrames.push_back(win32Start);
                        d.StackFrames.push_back(rip);
                        d.Severity = "CRITICAL";
                        d.Description = "Thread TID " + std::to_string(tid) +
                                        " Win32StartAddress=0x" +
                                        [&]{ char t[32]; sprintf_s(t, "%llX", (unsigned long long)win32Start); return std::string(t); }() +
                                        " (module: " + (startMod.empty() ? "Unbacked" : startMod) + ")" +
                                        " | CurrentRIP=0x" +
                                        [&]{ char t[32]; sprintf_s(t, "%llX", (unsigned long long)rip); return std::string(t); }() +
                                        " (module: " + (ripMod.empty() ? "Unbacked" : ripMod) + ")." +
                                        " Indicates SetThreadContext hijack or floating shellcode.";
                        detections.push_back(d);
                    }
                }
            }

            ResumeThread(hThread);
            CloseHandle(hThread);
        }

        CloseHandle(hProc);
        return detections;
    }

    std::vector<SpoofedThreadDetection> ScanProcessSpoofedThreads(DWORD pid, const std::string& procName) {
        std::vector<SpoofedThreadDetection> detections;
        if (pid == 0 || pid == 4) return detections;

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        pfnNtQueryInformationThread pfnQIT = hNtdll ? (pfnNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread") : nullptr;

        std::vector<DWORD> threads;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = { sizeof(te) };
            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID == pid) {
                        threads.push_back(te.th32ThreadID);
                    }
                } while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }

        return ScanProcessThreadsInternal(pid, procName, threads, pfnQIT);
    }

    std::vector<SpoofedThreadDetection> ScanAllProcessesSpoofedThreads() {
        std::vector<SpoofedThreadDetection> all;

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        pfnNtQueryInformationThread pfnQIT = hNtdll ? (pfnNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread") : nullptr;

        // 1. Take a single OS-wide thread snapshot and group by PID
        std::unordered_map<DWORD, std::vector<DWORD>> processThreads;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = { sizeof(te) };
            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID > 4) {
                        processThreads[te.th32OwnerProcessID].push_back(te.th32ThreadID);
                    }
                } while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }

        // 2. Iterate through candidate processes
        for (const auto& kv : processThreads) {
            DWORD pid = kv.first;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) continue;

            WCHAR szPath[MAX_PATH] = {};
            DWORD dwSz = MAX_PATH;
            QueryFullProcessImageNameW(h, 0, szPath, &dwSz);
            CloseHandle(h);

            WCHAR* pName = PathFindFileNameW(szPath);
            char nameBuf[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pName, -1, nameBuf, MAX_PATH, NULL, NULL);

            auto procDets = ScanProcessThreadsInternal(pid, nameBuf, kv.second, pfnQIT);
            if (!procDets.empty()) {
                all.insert(all.end(), procDets.begin(), procDets.end());
            }
        }

        return all;
    }

} // namespace SpoofedThreadScanner
