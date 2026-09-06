#include "HookScanner.hpp"
#include "SyscallEngine.hpp"
#include "PEParser.hpp"
#include <psapi.h>
#include <shlwapi.h>
#include <iostream>
#include <algorithm>

namespace HookScanner {

    std::vector<ClbDllDetection> ScanSystemClbDll() {
        std::vector<ClbDllDetection> results;
        std::vector<std::wstring> paths = {
            L"C:\\Windows\\System32\\clb.dll",
            L"C:\\Windows\\SysWOW64\\clb.dll"
        };

        for (const auto& path : paths) {
            DWORD attr = GetFileAttributesW(path.c_str());
            if (attr == INVALID_FILE_ATTRIBUTES) {
                continue; // File does not exist, which is normal on modern Windows
            }

            ClbDllDetection det;
            det.FilePath = path;
            det.Exists = true;
            det.IsMicrosoftSigned = false;
            det.IsRogueHookDll = false;

            PE::PEImage pe;
            if (pe.LoadFromFile(path)) {
                det.SHA256 = PE::PEImage::ComputeSHA256(pe.GetRawBuffer());
                auto cert = pe.ParseCertificate(path);
                det.IsMicrosoftSigned = cert.IsMicrosoftSigned || cert.IsTrusted;
                det.SignerSubject = cert.SubjectName;

                // Only record if it's a non-Microsoft rogue payload
                if (!det.IsMicrosoftSigned) {
                    det.IsRogueHookDll = true;
                    det.Severity = "CRITICAL";
                    det.Description = "Rogue unsigned/forged 'clb.dll' detected in system directory. Active RegHook payload!";
                    results.push_back(det);
                }
            }
            else {
                det.IsRogueHookDll = true;
                det.Severity = "CRITICAL";
                det.Description = "Corrupted or non-PE clb.dll found in system directory.";
                results.push_back(det);
            }
        }

        return results;
    }

    static std::string ResolveAddressToModule(HANDLE hProc, ULONG_PTR addr) {
        char szMapped[MAX_PATH] = { 0 };
        if (GetMappedFileNameA(hProc, (LPVOID)addr, szMapped, MAX_PATH) > 0) {
            char* pBaseName = PathFindFileNameA(szMapped);
            return std::string(pBaseName);
        }

        // Check if unbacked
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T retLen;
        if (NT_SUCCESS(SyscallEngine::DirectNtQueryVirtualMemory(hProc, (PVOID)addr, MemoryBasicInformationEx, &mbi, sizeof(mbi), &retLen))) {
            if (mbi.Type == MEM_PRIVATE) {
                return "Unbacked Private Memory (Shellcode/Manual Map)";
            }
            else if (mbi.Type == MEM_MAPPED) {
                return "Mapped Section (No DLL Identity)";
            }
        }
        return "Unknown Location";
    }

    std::vector<HookDetection> ScanApiHooks(DWORD pid, const std::string& procName) {
        std::vector<HookDetection> detections;

        // Skip Chromium / Edge WebView2 / Electron sandbox processes (they use internal sandbox hooks)
        std::string lowerProc = procName;
        std::transform(lowerProc.begin(), lowerProc.end(), lowerProc.begin(), ::tolower);
        if (lowerProc.find("msedgewebview2") != std::string::npos ||
            lowerProc.find("msedge") != std::string::npos ||
            lowerProc.find("chrome") != std::string::npos ||
            lowerProc.find("discord") != std::string::npos ||
            lowerProc.find("slack") != std::string::npos ||
            lowerProc.find("code.exe") != std::string::npos ||
            lowerProc.find("antigravity") != std::string::npos) {
            return detections;
        }

        static const std::vector<std::string> criticalApis = {
            "NtOpenKey",
            "NtOpenKeyEx",
            "NtEnumerateKey",
            "NtEnumerateValueKey",
            "NtQueryKey",
            "NtQueryValueKey",
            "NtSetValueKey",
            "NtDeleteKey",
            "NtReadVirtualMemory",
            "NtWriteVirtualMemory",
            "NtProtectVirtualMemory",
            "NtQueueApcThread"
        };

        // Read clean ntdll from disk once
        static PE::PEImage diskNtdll;
        static bool isLoaded = diskNtdll.LoadFromFile(L"C:\\Windows\\System32\\ntdll.dll");
        if (!isLoaded) {
            return detections;
        }

        HANDLE hProc = NULL;
        OBJECT_ATTRIBUTES_EX objAttr = { sizeof(OBJECT_ATTRIBUTES_EX) };
        CLIENT_ID_EX cid = { (HANDLE)(ULONG_PTR)pid, NULL };

        NTSTATUS status = SyscallEngine::DirectNtOpenProcess(
            &hProc,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            &objAttr,
            &cid
        );

        if (!NT_SUCCESS(status) || !hProc) {
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        }
        if (!hProc) return detections;
        // In 64-bit Windows, ntdll is mapped at identical virtual base across all processes
        HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");
        ULONG_PTR targetNtdllBase = (ULONG_PTR)localNtdll;
        if (!targetNtdllBase) {
            CloseHandle(hProc);
            return detections;
        }

        for (const auto& apiName : criticalApis) {
            FARPROC localFunc = GetProcAddress(localNtdll, apiName.c_str());
            if (!localFunc) continue;

            DWORD rva = (DWORD)((ULONG_PTR)localFunc - (ULONG_PTR)localNtdll);
            ULONG_PTR targetFuncAddr = targetNtdllBase + rva;

            // Read clean bytes from disk PE image
            DWORD fileOffset = diskNtdll.RvaToOffset(rva);
            if (!fileOffset || fileOffset + 16 > diskNtdll.GetRawBuffer().size()) continue;

            const BYTE* diskCode = diskNtdll.GetRawBuffer().data() + fileOffset;

            // Read in-memory bytes from target process
            BYTE memCode[16] = { 0 };
            SIZE_T bytesRead = 0;
            NTSTATUS rStatus = SyscallEngine::DirectNtReadVirtualMemory(
                hProc,
                (PVOID)targetFuncAddr,
                memCode,
                sizeof(memCode),
                &bytesRead
            );

            if (!NT_SUCCESS(rStatus) || bytesRead < 8) continue;

            // Compare with on-disk clean prologue
            if (memcmp(diskCode, memCode, 8) != 0) {
                HookDetection det;
                det.ProcessId = pid;
                det.ProcessName = procName;
                det.TargetFunction = "ntdll.dll!" + apiName;
                det.FunctionAddress = targetFuncAddr;
                det.CleanDiskBytes.assign(diskCode, diskCode + 16);
                det.HookedMemoryBytes.assign(memCode, memCode + 16);
                det.HookDestination = 0;

                bool isConfirmedHook = false;

                // Identify common hook patterns
                if (memCode[0] == 0xE9) { // 32-bit relative JMP
                    LONG rel32 = *(LONG*)&memCode[1];
                    det.HookDestination = targetFuncAddr + 5 + rel32;
                    det.HookType = "INLINE_DETOUR_JMP32 (Direct JMP)";
                    isConfirmedHook = true;
                }
                else if (memCode[0] == 0xFF && memCode[1] == 0x25) { // 64-bit indirect JMP
                    if (bytesRead >= 14 && memCode[2] == 0 && memCode[3] == 0 && memCode[4] == 0 && memCode[5] == 0) {
                        det.HookDestination = *(ULONG_PTR*)&memCode[6];
                        det.HookType = "INLINE_DETOUR_JMP64 (64-bit Absolute Hook)";
                        isConfirmedHook = true;
                    }
                    else {
                        LONG rel32 = *(LONG*)&memCode[2];
                        ULONG_PTR ptrAddr = targetFuncAddr + 6 + rel32;
                        ULONG_PTR target = 0;
                        SIZE_T r = 0;
                        SyscallEngine::DirectNtReadVirtualMemory(hProc, (PVOID)ptrAddr, &target, sizeof(target), &r);
                        det.HookDestination = target;
                        det.HookType = "INLINE_DETOUR_JMP64 (64-bit Indirect Hook)";
                        isConfirmedHook = true;
                    }
                }
                else if (memCode[0] == 0x48 && memCode[1] == 0xB8) { // mov rax, <64-bit addr>; jmp rax
                    det.HookDestination = *(ULONG_PTR*)&memCode[2];
                    det.HookType = "MOV_RAX_JMP_RAX (Inline Trampoline)";
                    isConfirmedHook = true;
                }
                else if (memCode[0] == 0xCC || memCode[0] == 0xC3) { // Software breakpoint / early return hook
                    det.HookType = "INT3_OR_RET_PATCH";
                    isConfirmedHook = true;
                }

                // If in-memory code is just normal mov r10, rcx (4C 8B D1), it's standard OS syscall
                if (memCode[0] == 0x4C && memCode[1] == 0x8B && memCode[2] == 0xD1) {
                    isConfirmedHook = false;
                }

                if (isConfirmedHook) {
                    if (det.HookDestination) {
                        det.DestinationModule = ResolveAddressToModule(hProc, det.HookDestination);
                    }
                    else {
                        det.DestinationModule = "Unknown";
                    }

                    std::string lowerDest = det.DestinationModule;
                    std::transform(lowerDest.begin(), lowerDest.end(), lowerDest.begin(), ::tolower);
                    // Filter browser sandbox destinations
                    if (lowerDest.find("msedgewebview2") == std::string::npos &&
                        lowerDest.find("chrome") == std::string::npos &&
                        lowerDest.find("discord") == std::string::npos) {
                        det.Severity = "CRITICAL";
                        det.Description = "Registry / Core NT API hooked! Execution redirected to " + det.DestinationModule + " (Target: 0x" + std::to_string(det.HookDestination) + ")";
                        detections.push_back(det);
                    }
                }
            }
        }

        CloseHandle(hProc);
        return detections;
    }

    std::vector<HookDetection> ScanAllProcessHooks() {
        std::vector<HookDetection> allHooks;

        DWORD pids[2048];
        DWORD cbNeeded = 0;
        if (!EnumProcesses(pids, sizeof(pids), &cbNeeded)) return allHooks;

        DWORD count = cbNeeded / sizeof(DWORD);
        for (DWORD i = 0; i < count; i++) {
            DWORD pid = pids[i];
            if (pid == 0 || pid == 4) continue;

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
            if (procName.empty()) procName = "PID_" + std::to_string(pid);

            auto hooks = ScanApiHooks(pid, procName);
            allHooks.insert(allHooks.end(), hooks.begin(), hooks.end());
        }

        return allHooks;
    }
}
