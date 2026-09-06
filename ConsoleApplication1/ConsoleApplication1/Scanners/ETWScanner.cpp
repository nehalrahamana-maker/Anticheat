#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "ETWScanner.hpp"
#include "SyscallEngine.hpp"
#include "PEParser.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9
#endif

typedef NTSTATUS(NTAPI* pfnNtQueryInformationThread)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

namespace ETWScanner {

    static std::string ToHex(const BYTE* data, size_t len) {
        std::ostringstream oss;
        for (size_t i = 0; i < len; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
        }
        return oss.str();
    }

    std::vector<ETWDetection> ScanProcessETWIntegrity(DWORD pid, const std::string& procName) {
        std::vector<ETWDetection> detections;

        // Skip system kernel PIDs and idle
        if (pid == 0 || pid == 4) return detections;

        // Skip browser sandbox helper processes if desired, but we scan games & target binaries
        std::string lowerProc = procName;
        std::transform(lowerProc.begin(), lowerProc.end(), lowerProc.begin(), ::tolower);
        if (lowerProc.find("msedgewebview2") != std::string::npos ||
            lowerProc.find("chrome") != std::string::npos ||
            lowerProc.find("discord") != std::string::npos ||
            lowerProc.find("slack") != std::string::npos) {
            return detections;
        }

        static const std::vector<std::string> etwApis = {
            "EtwEventWrite",
            "EtwEventWriteFull",
            "EtwEventWriteNoRegistration",
            "EtwSendNotification",
            "EtwEventRegister",
            "EtwEventUnregister",
            "NtTraceEvent"
        };

        static PE::PEImage diskNtdll;
        static bool isLoaded = diskNtdll.LoadFromFile(L"C:\\Windows\\System32\\ntdll.dll");
        if (!isLoaded) return detections;

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

        HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");
        ULONG_PTR targetNtdllBase = (ULONG_PTR)localNtdll;
        if (!targetNtdllBase) {
            CloseHandle(hProc);
            return detections;
        }

        for (const auto& apiName : etwApis) {
            FARPROC localFunc = GetProcAddress(localNtdll, apiName.c_str());
            if (!localFunc) continue;

            DWORD rva = (DWORD)((ULONG_PTR)localFunc - (ULONG_PTR)localNtdll);
            ULONG_PTR targetFuncAddr = targetNtdllBase + rva;

            DWORD fileOffset = diskNtdll.RvaToOffset(rva);
            if (!fileOffset || fileOffset + 16 > diskNtdll.GetRawBuffer().size()) continue;

            const BYTE* diskCode = diskNtdll.GetRawBuffer().data() + fileOffset;

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

            // Check for ETW bypass patterns
            bool isTampered = false;
            std::string technique;
            std::string desc;

            if (memCode[0] == 0xC3) {
                // Immediate RET patch
                isTampered = true;
                technique = "ETW_PROLOGUE_PATCH_RET";
                desc = "Immediate RET (0xC3) patch silencing " + apiName + " event telemetry!";
            }
            else if ((memCode[0] == 0x31 && memCode[1] == 0xC0 && memCode[2] == 0xC3) ||
                     (memCode[0] == 0x33 && memCode[1] == 0xC0 && memCode[2] == 0xC3)) {
                // XOR EAX, EAX; RET (returns STATUS_SUCCESS silently)
                isTampered = true;
                technique = "ETW_PROLOGUE_PATCH_XOR_EAX";
                desc = "XOR EAX, EAX; RET (31 C0 C3) patch faking success for " + apiName;
            }
            else if (memCode[0] == 0x48 && memCode[1] == 0x31 && memCode[2] == 0xC0 && memCode[3] == 0xC3) {
                // XOR RAX, RAX; RET
                isTampered = true;
                technique = "ETW_PROLOGUE_PATCH_XOR_RAX";
                desc = "XOR RAX, RAX; RET patch faking success for " + apiName;
            }
            else if (memCode[0] == 0xB8 && memCode[5] == 0xC3) {
                // MOV EAX, imm32; RET
                isTampered = true;
                technique = "ETW_PROLOGUE_PATCH_MOV_EAX_RET";
                desc = "MOV EAX, imm32; RET patch altering return code for " + apiName;
            }
            else if (memCode[0] == 0xE9) {
                // JMP detour hook
                isTampered = true;
                technique = "ETW_INLINE_DETOUR_JMP";
                desc = "JMP relative detour redirecting " + apiName + " to external memory stub";
            }
            else if (memCode[0] == 0xFF && memCode[1] == 0x25) {
                // Indirect JMP hook
                isTampered = true;
                technique = "ETW_INLINE_HOOK_JMP64";
                desc = "64-bit indirect JMP detour on " + apiName;
            }
            else if (memcmp(diskCode, memCode, 8) != 0) {
                // Byte mismatch against clean disk
                isTampered = true;
                technique = "ETW_PROLOGUE_BYTE_DIFF";
                desc = "In-memory bytes of " + apiName + " differ from verified disk PE image.";
            }

            if (isTampered) {
                ETWDetection det;
                det.ProcessId = pid;
                det.ProcessName = procName;
                det.TargetFunction = "ntdll.dll!" + apiName;
                det.FunctionAddress = targetFuncAddr;
                det.TamperTechnique = technique;
                det.CleanDiskBytes.assign(diskCode, diskCode + 16);
                det.TamperedMemoryBytes.assign(memCode, memCode + 16);
                det.Severity = "CRITICAL";
                det.Description = desc;
                detections.push_back(det);
            }
        }

    // 5. Detect NtSetContextThread hook in ntdll (bypasses EventLog Phant0m thread-suspend check)
    //    Cheats use this instead of SuspendThread to redirect EventLog service threads without
    //    incrementing the suspend count that our Phant0m check reads.
    {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            static const std::vector<std::string> threadHijackApis = {
                "NtSetContextThread",
                "NtSuspendThread",
                "NtTerminateThread"
            };

            static PE::PEImage diskNtdllLocal;
            static bool diskLoaded = diskNtdllLocal.LoadFromFile(L"C:\\Windows\\System32\\ntdll.dll");

            if (diskLoaded) {
                for (const auto& api : threadHijackApis) {
                    FARPROC pFunc = GetProcAddress(hNtdll, api.c_str());
                    if (!pFunc) continue;

                    DWORD rva = (DWORD)((ULONG_PTR)pFunc - (ULONG_PTR)hNtdll);
                    DWORD fileOff = diskNtdllLocal.RvaToOffset(rva);
                    if (!fileOff || fileOff + 16 > diskNtdllLocal.GetRawBuffer().size()) continue;

                    const BYTE* diskBytes = diskNtdllLocal.GetRawBuffer().data() + fileOff;
                    const BYTE* memBytes  = (const BYTE*)pFunc;

                    bool hooked = false;
                    std::string hookTech;

                    if (memBytes[0] == 0xC3) {
                        hooked = true; hookTech = "ETW_NTDLL_HOOK_RET_PATCH";
                    } else if (memBytes[0] == 0xE9) {
                        hooked = true; hookTech = "ETW_NTDLL_HOOK_JMP32";
                    } else if (memBytes[0] == 0xFF && memBytes[1] == 0x25) {
                        hooked = true; hookTech = "ETW_NTDLL_HOOK_JMP64";
                    } else if (memcmp(diskBytes, memBytes, 8) != 0) {
                        hooked = true; hookTech = "ETW_NTDLL_HOOK_BYTE_DIFF";
                    }

                    if (hooked) {
                        ETWDetection det;
                        det.ProcessId        = GetCurrentProcessId();
                        det.ProcessName      = "ntdll.dll (scanner process)";
                        det.TargetFunction   = "ntdll.dll!" + api;
                        det.FunctionAddress  = (ULONG_PTR)pFunc;
                        det.TamperTechnique  = hookTech;
                        det.CleanDiskBytes.assign(diskBytes, diskBytes + 16);
                        det.TamperedMemoryBytes.assign(memBytes, memBytes + 16);
                        det.Severity         = "CRITICAL";
                        det.Description      = api + " is hooked in the scanner process ntdll — "
                                               "cheat is intercepting thread control APIs to bypass "
                                               "EventLog Phant0m suspend-count detection and scanner "
                                               "thread auditing. Hook technique: " + hookTech;
                        detections.push_back(det);
                    }
                }
            }
        }
    }

    CloseHandle(hProc);
    return detections;
}

std::vector<ETWDetection> ScanEventLogServiceTampering() {
    std::vector<ETWDetection> detections;

        // 1. Query SCM for the PID of the 'EventLog' service
        SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if (!hSCM) return detections;

        SC_HANDLE hService = OpenServiceW(hSCM, L"EventLog", SERVICE_QUERY_STATUS);
        if (!hService) {
            CloseServiceHandle(hSCM);
            return detections;
        }

        DWORD dwBytesNeeded = 0;
        SERVICE_STATUS_PROCESS ssp = {};
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &dwBytesNeeded)) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return detections;
        }

        DWORD eventLogPid = ssp.dwProcessId;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);

        if (eventLogPid == 0) {
            ETWDetection det;
            det.ProcessId = 0;
            det.ProcessName = "services.exe / svchost.exe";
            det.TargetFunction = "EventLog Service";
            det.TamperTechnique = "EVENTLOG_SERVICE_STOPPED";
            det.Severity = "CRITICAL";
            det.Description = "Windows Event Log service is NOT RUNNING or disabled. Critical forensic blindspot!";
            detections.push_back(det);
            return detections;
        }

        // 2. Open EventLog hosting svchost.exe
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, eventLogPid);
        if (!hProc) return detections;

        // 3. Locate wevtsvc.dll base and size in this svchost.exe
        ULONG_PTR wevtsvcBase = 0;
        DWORD wevtsvcSize = 0;
        HANDLE hSnapMod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, eventLogPid);
        if (hSnapMod != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me = {};
            me.dwSize = sizeof(me);
            if (Module32FirstW(hSnapMod, &me)) {
                do {
                    std::wstring modName = me.szModule;
                    std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);
                    if (modName.find(L"wevtsvc.dll") != std::wstring::npos) {
                        wevtsvcBase = (ULONG_PTR)me.modBaseAddr;
                        wevtsvcSize = me.modBaseSize;
                        break;
                    }
                } while (Module32NextW(hSnapMod, &me));
            }
            CloseHandle(hSnapMod);
        }

        // 4. Verify wevtsvc.dll code section integrity against disk if loaded
        if (wevtsvcBase > 0) {
            PE::PEImage diskWevtsvc;
            if (diskWevtsvc.LoadFromFile(L"C:\\Windows\\System32\\wevtsvc.dll")) {
                const auto& sections = diskWevtsvc.GetSections();
                for (const auto& sec : sections) {
                    if (sec.Name == ".text" && sec.VirtualSize > 0) {
                        std::vector<BYTE> memSec(sec.VirtualSize, 0);
                        SIZE_T br = 0;
                        NTSTATUS st = SyscallEngine::DirectNtReadVirtualMemory(
                            hProc, (PVOID)(wevtsvcBase + sec.VirtualAddress), memSec.data(), sec.VirtualSize, &br);

                        if (NT_SUCCESS(st) && br >= sec.VirtualSize) {
                            if (sec.RawOffset + sec.RawSize <= diskWevtsvc.GetRawBuffer().size()) {
                                const BYTE* diskData = diskWevtsvc.GetRawBuffer().data() + sec.RawOffset;
                                size_t compareLen = ((size_t)sec.VirtualSize < (size_t)sec.RawSize) ? (size_t)sec.VirtualSize : (size_t)sec.RawSize;
                                size_t patchCount = 0;
                                for (size_t i = 0; i < compareLen; i++) {
                                    if (memSec[i] != diskData[i]) patchCount++;
                                }
                                if (patchCount > 64) {
                                    ETWDetection det;
                                    det.ProcessId = eventLogPid;
                                    det.ProcessName = "svchost.exe (EventLog)";
                                    det.TargetFunction = "wevtsvc.dll!.text";
                                    det.FunctionAddress = wevtsvcBase + sec.VirtualAddress;
                                    det.TamperTechnique = "EVENTLOG_WEVTSVC_IN_MEMORY_PATCH";
                                    det.Severity = "CRITICAL";
                                    det.Description = "wevtsvc.dll code section has " + std::to_string(patchCount) +
                                                      " modified bytes in memory (Event Log hook / filter attack).";
                                    detections.push_back(det);
                                }
                            }
                        }
                    }
                }
            }
        }

        // 5. Enumerate all threads in the EventLog svchost and detect Phant0m thread suspension
        HANDLE hSnapThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapThread != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = {};
            te.dwSize = sizeof(te);
            if (Thread32First(hSnapThread, &te)) {
                HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
                pfnNtQueryInformationThread pfnQIT = nullptr;
                if (hNtdll) {
                    pfnQIT = (pfnNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
                }

                do {
                    if (te.th32OwnerProcessID != eventLogPid) continue;

                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                    if (!hThread) continue;

                    ULONG_PTR win32Start = 0;
                    if (pfnQIT) {
                        ULONG retLen = 0;
                        pfnQIT(hThread, ThreadQuerySetWin32StartAddress, &win32Start, sizeof(win32Start), &retLen);
                    }

                    // Check if thread is inside wevtsvc.dll address range
                    bool isWevtsvcThread = false;
                    if (wevtsvcBase > 0 && win32Start >= wevtsvcBase && win32Start < wevtsvcBase + wevtsvcSize) {
                        isWevtsvcThread = true;
                    }

                    // Check suspend count via Suspend/Resume
                    DWORD prevCount = SuspendThread(hThread);
                    if (prevCount != (DWORD)-1) {
                        ResumeThread(hThread); // Restore balance
                        if (prevCount > 0) {
                            // Thread was suspended by a 3rd party tool (Phant0m / EventLogCleaner attack!)
                            ETWDetection det;
                            det.ProcessId = eventLogPid;
                            det.ProcessName = "svchost.exe (EventLog)";
                            det.TargetFunction = "TID " + std::to_string(te.th32ThreadID) +
                                                 (isWevtsvcThread ? " (wevtsvc.dll Worker)" : " (Service Thread)");
                            det.FunctionAddress = win32Start;
                            det.TamperTechnique = "EVENTLOG_SERVICE_THREAD_SUSPENDED";
                            det.Severity = "CRITICAL";
                            det.Description = "EventLog worker thread (TID " + std::to_string(te.th32ThreadID) +
                                              ") is SUSPENDED (SuspendCount=" + std::to_string(prevCount) +
                                              ")! Classic Phant0m / Event-Log-Cleaner bypass detected.";
                            detections.push_back(det);
                        }
                    }

                    CloseHandle(hThread);
                } while (Thread32Next(hSnapThread, &te));
            }
            CloseHandle(hSnapThread);
        }

        CloseHandle(hProc);
        return detections;
    }

    std::vector<ETWDetection> ScanAllProcessesETW() {
        std::vector<ETWDetection> all;

        // 1. Audit Event Log Service integrity (Phant0m / wevtsvc attack)
        auto svcDets = ScanEventLogServiceTampering();
        all.insert(all.end(), svcDets.begin(), svcDets.end());

        // 2. Audit all active user-mode processes for ETW function patching
        DWORD pids[2048] = {};
        DWORD needed = 0;
        if (EnumProcesses(pids, sizeof(pids), &needed)) {
            DWORD count = needed / sizeof(DWORD);
            for (DWORD i = 0; i < count; i++) {
                DWORD pid = pids[i];
                if (pid == 0 || pid == 4) continue;

                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (!h) continue;

                WCHAR szPath[MAX_PATH] = {};
                DWORD dwSz = MAX_PATH;
                QueryFullProcessImageNameW(h, 0, szPath, &dwSz);
                CloseHandle(h);

                WCHAR* pName = PathFindFileNameW(szPath);
                char nameBuf[MAX_PATH] = {};
                WideCharToMultiByte(CP_UTF8, 0, pName, -1, nameBuf, MAX_PATH, NULL, NULL);

                auto procDets = ScanProcessETWIntegrity(pid, nameBuf);
                all.insert(all.end(), procDets.begin(), procDets.end());
            }
        }

        return all;
    }

} // namespace ETWScanner
