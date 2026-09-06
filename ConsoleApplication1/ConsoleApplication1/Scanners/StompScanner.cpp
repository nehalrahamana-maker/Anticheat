#include "StompScanner.hpp"
#include "SyscallEngine.hpp"
#include "PEParser.hpp"
#include <psapi.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

namespace StompScanner {

    bool IsCommonStompTarget(const std::string& moduleName) {
        std::string lower = moduleName;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        static const std::vector<std::string> knownTargets = {
            "prnntfy.dll",
            "winspool.drv",
            "printui.dll",
            "mswsock.dll",
            "combase.dll",
            "propsys.dll",
            "wintrust.dll",
            "version.dll",
            "cryptbase.dll",
            "uxtheme.dll",
            "clbcatq.dll",
            "oleaut32.dll",
            "userenv.dll",
            "netapi32.dll",
            "samcli.dll",
            "rasapi32.dll",
            "uvh64.dll",
            "uvh64_orig.dll",
            "nvspcap64.dll",
            "d3d11.dll",
            "dxgi.dll",
            "amsi.dll",
            "gameoverlayrenderer64.dll",
            "discordhook64.dll"
        };

        for (const auto& target : knownTargets) {
            if (lower == target || lower.find(target) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    static std::string ProtectionToString(DWORD protect) {
        switch (protect & 0xFF) {
        case PAGE_EXECUTE: return "PAGE_EXECUTE";
        case PAGE_EXECUTE_READ: return "PAGE_EXECUTE_READ (Normal Code)";
        case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE (RWX - Highly Suspicious!)";
        case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY (WriteCopy - Modified)";
        case PAGE_NOACCESS: return "PAGE_NOACCESS";
        case PAGE_READONLY: return "PAGE_READONLY";
        case PAGE_READWRITE: return "PAGE_READWRITE (Data Page / Stripped Code)";
        case PAGE_WRITECOPY: return "PAGE_WRITECOPY";
        default: return "UNKNOWN (" + std::to_string(protect) + ")";
        }
    }

    static std::string AnalyzeByteDifference(const std::vector<BYTE>& disk, const std::vector<BYTE>& mem) {
        if (mem.size() < 5) return "GENERIC_MODIFICATION";

        // Check for 5-byte JMP (Detours / inline hook)
        if (mem[0] == 0xE9) {
            return "TRAMPOLINE_JMP_REL32 (Detour Hook)";
        }
        // Check for 64-bit absolute indirect JMP (FF 25 00 00 00 00 [addr])
        if (mem.size() >= 14 && mem[0] == 0xFF && mem[1] == 0x25) {
            return "TRAMPOLINE_JMP_QWORD (64-bit Detour / Proxy)";
        }
        // Check for shellcode function prologs
        if (mem.size() >= 3 && mem[0] == 0x48 && mem[1] == 0x83 && mem[2] == 0xEC) {
            return "SHELLCODE_PROLOG (Stack Frame Allocation)";
        }
        if (mem.size() >= 4 && mem[0] == 0xFC && mem[1] == 0x48 && mem[2] == 0x83) {
            return "MSF_PAYLOAD_PATTERN (Cobalt / Metasploit Header)";
        }
        // Check if all memory is zeroed (code stripping / unmapping)
        bool allZero = true;
        for (size_t i = 0; i < (std::min)((size_t)64, mem.size()); i++) {
            if (mem[i] != 0x00) {
                allZero = false;
                break;
            }
        }
        if (allZero) return "CODE_ZEROED_OUT";

        // Check for full section replacement
        return "MODULE_STOMPED_PAYLOAD (Arbitrary Executable Code)";
    }

    std::vector<StompDetection> ScanProcess(DWORD pid, const std::string& procName) {
        std::vector<StompDetection> detections;

        HANDLE hProc = NULL;
        OBJECT_ATTRIBUTES_EX objAttr = { sizeof(OBJECT_ATTRIBUTES_EX) };
        CLIENT_ID_EX cid = { (HANDLE)(ULONG_PTR)pid, NULL };

        // Use direct syscall to open process handle
        NTSTATUS status = SyscallEngine::DirectNtOpenProcess(
            &hProc,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            &objAttr,
            &cid
        );

        if (!NT_SUCCESS(status) || !hProc) {
            // Fallback to Win32
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        }

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnap == INVALID_HANDLE_VALUE) {
            CloseHandle(hProc);
            return detections;
        }

        MODULEENTRY32W me;
        me.dwSize = sizeof(MODULEENTRY32W);

        if (!Module32FirstW(hSnap, &me)) {
            CloseHandle(hSnap);
            CloseHandle(hProc);
            return detections;
        }

        DWORD m = 0;
        do {
            m++;
            try {
                std::wstring modPathWs(me.szExePath);
                WCHAR* pFileName = PathFindFileNameW(me.szExePath);
                char modNameBuf[MAX_PATH] = { 0 };
                WideCharToMultiByte(CP_UTF8, 0, pFileName, -1, modNameBuf, MAX_PATH, NULL, NULL);
                std::string modName = modNameBuf;

                // Priority filter: focus strictly on known stomp target DLLs (version.dll, d3d11.dll, etc.)
                // or the main executable ONLY if it's the monitored game/emulator process
                std::string lowerProc = procName;
                std::transform(lowerProc.begin(), lowerProc.end(), lowerProc.begin(), ::tolower);
                bool isMonitoredGame = (lowerProc.find("hd-player") != std::string::npos ||
                                        lowerProc.find("freefire") != std::string::npos ||
                                        lowerProc.find("cheat") != std::string::npos ||
                                        lowerProc.find("bypass") != std::string::npos ||
                                        lowerProc.find("game") != std::string::npos ||
                                        lowerProc.find("loader") != std::string::npos);

                bool isTarget = IsCommonStompTarget(modName) || (m == 1 && isMonitoredGame);
                if (!isTarget) continue;

                // Load or get cached on-disk PE image
                static std::map<std::wstring, std::shared_ptr<PE::PEImage>> s_PeCache;
                std::shared_ptr<PE::PEImage> pDiskPE;
                auto it = s_PeCache.find(modPathWs);
                if (it != s_PeCache.end()) {
                    pDiskPE = it->second;
                }
                else {
                    pDiskPE = std::make_shared<PE::PEImage>();
                    if (pDiskPE->LoadFromFile(modPathWs)) {
                        s_PeCache[modPathWs] = pDiskPE;
                    }
                    else {
                        pDiskPE = nullptr;
                    }
                }

                if (!pDiskPE || !pDiskPE->IsValid()) {
                    continue;
                }

                // Get mapped disk image and apply relocations for the loaded module base
                ULONG_PTR loadedBase = (ULONG_PTR)me.modBaseAddr;
                std::vector<BYTE> mappedDisk = pDiskPE->GetMappedImage();
                if (mappedDisk.empty()) continue;

                // Apply base relocations so ASLR addresses match memory
                pDiskPE->ApplyRelocations(mappedDisk, loadedBase);

                // Iterate executable sections (.text, etc.)
                for (const auto& sec : pDiskPE->GetSections()) {
                    if (!sec.IsExecutable || sec.VirtualSize == 0 || sec.Name == "fothk" || sec.Name.find("fothk") != std::string::npos) continue;

                    DWORD secRVA = sec.VirtualAddress;
                    DWORD secSize = (sec.VirtualSize > 0) ? sec.VirtualSize : sec.RawSize;
                    if (secRVA + secSize > mappedDisk.size()) continue;

                    PVOID targetAddr = (PVOID)(loadedBase + secRVA);

                    // 1. Query memory protection of this section in target process
                    MEMORY_BASIC_INFORMATION mbi = { 0 };
                    SIZE_T retLen = 0;
                    NTSTATUS qStatus = SyscallEngine::DirectNtQueryVirtualMemory(
                        hProc,
                        targetAddr,
                        MemoryBasicInformationEx,
                        &mbi,
                        sizeof(mbi),
                        &retLen
                    );

                    std::string memProtStr = "UNKNOWN";
                    bool isProtAnomalous = false;
                    if (NT_SUCCESS(qStatus)) {
                        memProtStr = ProtectionToString(mbi.Protect);
                        if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY) {
                            isProtAnomalous = true;
                        }
                    }

                    // 2. Read the in-memory section bytes using Direct Syscall
                    std::vector<BYTE> memSec(secSize, 0);
                    SIZE_T bytesRead = 0;
                    NTSTATUS rStatus = SyscallEngine::DirectNtReadVirtualMemory(
                        hProc,
                        targetAddr,
                        memSec.data(),
                        secSize,
                        &bytesRead
                    );

                    if (!NT_SUCCESS(rStatus) || bytesRead < (secSize / 2)) {
                        continue; // Skip if unreadable or guarded
                    }
                    memSec.resize(bytesRead);

                    // 3. Compare relocated disk section vs in-memory section
                    const BYTE* diskSecPtr = mappedDisk.data() + secRVA;
                    DWORD compareSize = (DWORD)(std::min)((SIZE_T)bytesRead, (SIZE_T)sec.VirtualSize);
                    if (compareSize == 0) continue;

                    // FAST PATH: SIMD memcmp check
                    if (memcmp(diskSecPtr, memSec.data(), compareSize) == 0 && !isProtAnomalous) {
                        continue; // 100% byte-exact match, skip diff analysis
                    }

                    DWORD modifiedCount = 0;
                    DWORD firstModOffset = 0xFFFFFFFF;

                    for (DWORD i = 0; i < compareSize; i++) {
                        if (diskSecPtr[i] != memSec[i]) {
                            if (firstModOffset == 0xFFFFFFFF) {
                                firstModOffset = i;
                            }
                            modifiedCount++;
                        }
                    }

                    // If modifications detected or suspicious protection
                    if (modifiedCount > 0 || isProtAnomalous) {
                        std::string diskHash = PE::PEImage::ComputeSHA256(diskSecPtr, compareSize);
                        std::string memHash = PE::PEImage::ComputeSHA256(memSec.data(), compareSize);

                        if (diskHash != memHash || isProtAnomalous) {
                            StompDetection d;
                            d.ProcessId = pid;
                            d.ProcessName = procName;
                            d.ModuleName = modName;
                            d.ModulePath = modPathWs;
                            d.ModuleBase = loadedBase;
                            d.SectionName = sec.Name;
                            d.SectionRVA = secRVA;
                            d.SectionSize = secSize;
                            d.DiskHash = diskHash;
                            d.MemoryHash = memHash;
                            d.ModifiedBytesCount = modifiedCount;
                            d.FirstModifiedOffset = (firstModOffset == 0xFFFFFFFF) ? 0 : firstModOffset;
                            d.MemoryProtection = memProtStr;

                            // Extract first 128 bytes sample around the modification
                            DWORD sampleOffset = (firstModOffset == 0xFFFFFFFF) ? 0 : firstModOffset;
                            DWORD sampleLen = (std::min)((DWORD)128, compareSize - sampleOffset);

                            d.DiskSample.assign(diskSecPtr + sampleOffset, diskSecPtr + sampleOffset + sampleLen);
                            d.MemorySample.assign(memSec.data() + sampleOffset, memSec.data() + sampleOffset + sampleLen);

                            d.HeuristicType = AnalyzeByteDifference(d.DiskSample, d.MemorySample);

                            // Skip benign loader relocation adjustments on non-target system modules if < 5 bytes and no hook trampoline
                            if (modifiedCount <= 4 && !isProtAnomalous && !IsCommonStompTarget(modName)) {
                                if (d.HeuristicType.find("TRAMPOLINE") == std::string::npos && d.HeuristicType.find("SHELLCODE") == std::string::npos) {
                                    continue;
                                }
                            }

                            if (IsCommonStompTarget(modName)) {
                                d.Severity = "CRITICAL";
                                d.Description = "High-priority stomp victim '" + modName + "' modified in memory. Relocations verified, modification confirmed.";
                            }
                            else if (modifiedCount > 64) {
                                d.Severity = "CRITICAL";
                                d.Description = "Massive in-memory code modification (" + std::to_string(modifiedCount) + " bytes changed). Complete module payload overwrite.";
                            }
                            else if (isProtAnomalous) {
                                d.Severity = "HIGH";
                                d.Description = "Executable section memory protection changed to " + memProtStr + " with code patch.";
                            }
                            else {
                                d.Severity = "HIGH";
                                d.Description = "Inline hook / trampoline patch detected inside " + sec.Name + " section.";
                            }

                            detections.push_back(d);
                        }
                    }
                }
            }
            catch (...) {}
        } while (Module32NextW(hSnap, &me));

        CloseHandle(hSnap);

        // Check for Hardware Breakpoint Hooks (hvci_hook.h / Dr0-Dr7)
        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te;
            te.dwSize = sizeof(THREADENTRY32);
            if (Thread32First(hThreadSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID == pid) {
                        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
                        if (hThread) {
                            CONTEXT ctx;
                            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                            if (GetThreadContext(hThread, &ctx)) {
                                if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 || (ctx.Dr7 & 0xFF) != 0) {
                                    StompDetection d;
                                    d.ProcessId = pid;
                                    d.ProcessName = procName;
                                    d.ModuleName = "THREAD_DEBUG_REGISTERS (TID " + std::to_string(te.th32ThreadID) + ")";
                                    d.SectionName = "DR0-DR7";
                                    d.HeuristicType = "HARDWARE_BREAKPOINT_HOOK (HVCI / VEH Hook)";
                                    d.Severity = "CRITICAL";
                                    d.Description = "Hardware Breakpoint (DR0=0x" + std::to_string(ctx.Dr0) + ", DR7=0x" + std::to_string(ctx.Dr7) + ") active on thread. Defeats hvci_hook.h / page-less hook.";
                                    detections.push_back(d);
                                }
                            }
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hThreadSnap, &te));
            }
            CloseHandle(hThreadSnap);
        }

        CloseHandle(hProc);
        return detections;
    }

    std::vector<StompDetection> ScanAllProcesses() {
        std::vector<StompDetection> allDetections;

        DWORD pids[2048];
        DWORD cbNeeded = 0;
        if (!EnumProcesses(pids, sizeof(pids), &cbNeeded)) return allDetections;

        DWORD numPids = cbNeeded / sizeof(DWORD);

        for (DWORD i = 0; i < numPids; i++) {
            DWORD pid = pids[i];
            if (pid == 0 || pid == 4) continue; // Skip System and Idle

            // Fast access check: skip protected / unreadable system processes
            HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!h) continue;

            WCHAR szName[MAX_PATH] = { 0 };
            DWORD dwSize = MAX_PATH;
            QueryFullProcessImageNameW(h, 0, szName, &dwSize);
            CloseHandle(h);

            WCHAR* pName = PathFindFileNameW(szName);
            char procNameBuf[MAX_PATH] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, pName, -1, procNameBuf, MAX_PATH, NULL, NULL);
            std::string procName = procNameBuf;
            if (procName.empty()) procName = "Process_" + std::to_string(pid);

            auto results = ScanProcess(pid, procName);
            allDetections.insert(allDetections.end(), results.begin(), results.end());
        }

        return allDetections;
    }
}
