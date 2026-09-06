#include "EmulatorScanner.hpp"
#include "SyscallEngine.hpp"
#include "PEParser.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

namespace EmulatorScanner {

    static std::string ToLower(const std::string& str) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower;
    }

    std::vector<EmulatorInstance> FindRunningEmulators() {
        std::vector<EmulatorInstance> instances;

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return instances;

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnap, &pe)) {
            do {
                char procNameBuf[MAX_PATH] = { 0 };
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, procNameBuf, MAX_PATH, NULL, NULL);
                std::string name = procNameBuf;
                std::string lower = ToLower(name);

                if (lower == "hd-player.exe" || lower == "hd-agent.exe" || lower == "bluestacks.exe" || 
                    lower == "msiappplayer.exe" || lower == "bstkheadless.exe" || lower == "bstksvc.exe") {
                    
                    EmulatorInstance inst;
                    inst.ProcessId = pe.th32ProcessID;
                    inst.ProcessName = name;
                    inst.IsRunning = true;
                    instances.push_back(inst);
                }
            } while (Process32NextW(hSnap, &pe));
        }

        CloseHandle(hSnap);

        // Find main window title
        for (auto& inst : instances) {
            struct WinCtx {
                DWORD targetPid;
                HWND  foundHwnd;
                std::string title;
            };
            WinCtx ctx = { inst.ProcessId, NULL, "" };

            EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                auto* p = reinterpret_cast<WinCtx*>(lParam);
                DWORD wndPid = 0;
                GetWindowThreadProcessId(hwnd, &wndPid);
                if (wndPid == p->targetPid && IsWindowVisible(hwnd)) {
                    char titleBuf[512] = { 0 };
                    GetWindowTextA(hwnd, titleBuf, sizeof(titleBuf));
                    if (strlen(titleBuf) > 0) {
                        p->foundHwnd = hwnd;
                        p->title = titleBuf;
                        return FALSE;
                    }
                }
                return TRUE;
            }, (LPARAM)&ctx);

            inst.MainWindowHandle = ctx.foundHwnd;
            inst.MainWindowTitle = ctx.title;
        }

        return instances;
    }

    std::vector<EmulatorDetection> ScanEmulatorIntegrity(DWORD pid, const std::string& procName) {
        std::vector<EmulatorDetection> detections;

        // 1. Audit core emulator modules loaded in memory
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me;
            me.dwSize = sizeof(MODULEENTRY32W);
            if (Module32FirstW(hSnap, &me)) {
                do {
                    char modNameBuf[MAX_PATH] = { 0 };
                    WCHAR* pFileName = PathFindFileNameW(me.szExePath);
                    WideCharToMultiByte(CP_UTF8, 0, pFileName, -1, modNameBuf, MAX_PATH, NULL, NULL);
                    std::string modNameLower = ToLower(modNameBuf);

                    if (modNameLower == "uvh64.dll" || modNameLower == "uvh64_orig.dll" ||
                        modNameLower == "minhook.x64.dll" || modNameLower == "speedhack.dll" ||
                        modNameLower.find("cheat") != std::string::npos || modNameLower.find("hack") != std::string::npos) {
                        
                        EmulatorDetection d;
                        d.ProcessId = pid;
                        d.ProcessName = procName;
                        d.DetectionType = "SUSPICIOUS_INJECTED_DLL";
                        d.Severity = "CRITICAL";
                        d.TargetObject = modNameBuf;
                        d.Description = "Known cheat/proxy DLL '" + std::string(modNameBuf) + "' injected into HD-Player emulator.";
                        detections.push_back(d);
                    }
                } while (Module32NextW(hSnap, &me));
            }
            CloseHandle(hSnap);
        }

        // 2. Global System Handle Table Audit (Double-call pattern for SystemHandleInformation)
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            auto pfnQuerySysInfo = (pfnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
            if (pfnQuerySysInfo) {
                ULONG len = 1024 * 1024; // 1 MB initial buffer
                std::vector<BYTE> buffer(len);
                ULONG retLen = 0;

                NTSTATUS qSt = pfnQuerySysInfo(SystemHandleInformation, buffer.data(), len, &retLen);
                if (qSt == 0xC0000004L) { // STATUS_INFO_LENGTH_MISMATCH
                    len = retLen + (128 * 1024);
                    buffer.resize(len);
                    qSt = pfnQuerySysInfo(SystemHandleInformation, buffer.data(), len, &retLen);
                }

                if (NT_SUCCESS(qSt)) {
                    auto* pInfo = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(buffer.data());
                    
                    for (ULONG i = 0; i < pInfo->NumberOfHandles; i++) {
                        const auto& hEntry = pInfo->Handles[i];
                        DWORD ownerPid = (DWORD)hEntry.UniqueProcessId;

                        // Check handles owned by other external processes
                        if (ownerPid != pid && ownerPid != GetCurrentProcessId() && ownerPid > 4) {
                            // Check if granted access has VM_READ (0x10) or VM_WRITE (0x20) or VM_OPERATION (0x8) or ALL_ACCESS
                            DWORD access = hEntry.GrantedAccess;
                            if ((access & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) != 0) {
                                // Duplicate handle to resolve target PID
                                HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ownerPid);
                                if (hOwner) {
                                    HANDLE hDup = NULL;
                                    if (DuplicateHandle(hOwner, (HANDLE)(ULONG_PTR)hEntry.HandleValue, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                                        DWORD targetPidOfHandle = GetProcessId(hDup);
                                        CloseHandle(hDup);

                                        if (targetPidOfHandle == pid) {
                                            // Handle specifically points to HD-Player.exe!
                                            WCHAR szOwnerPath[MAX_PATH] = { 0 };
                                            DWORD dwSz = MAX_PATH;
                                            QueryFullProcessImageNameW(hOwner, 0, szOwnerPath, &dwSz);

                                            WCHAR* pOwnerFile = PathFindFileNameW(szOwnerPath);
                                            char ownerNameBuf[MAX_PATH] = { 0 };
                                            WideCharToMultiByte(CP_UTF8, 0, pOwnerFile, -1, ownerNameBuf, MAX_PATH, NULL, NULL);
                                            std::string ownerName = ownerNameBuf;
                                            std::string ownerLower = ToLower(ownerName);

                                            // Filter legitimate OS system services
                                            if (ownerLower != "csrss.exe" && ownerLower != "services.exe" && ownerLower != "lsass.exe" &&
                                                ownerLower != "svchost.exe" && ownerLower != "taskmgr.exe" && ownerLower != "devenv.exe" &&
                                                ownerLower != "explorer.exe" && !ownerName.empty()) {
                                                
                                                EmulatorDetection d;
                                                d.ProcessId = pid;
                                                d.ProcessName = procName;
                                                d.DetectionType = "CRITICAL_EXTERNAL_MEMORY_READER";
                                                d.Severity = "CRITICAL";
                                                d.TargetObject = "Cheating Process: " + ownerName + " (PID " + std::to_string(ownerPid) + ")";
                                                d.Description = "Untrusted external process '" + ownerName + "' holds open read/write handle (0x" + 
                                                    std::to_string(hEntry.HandleValue) + ", Access=0x" + std::to_string(access) + 
                                                    ") to HD-Player.exe. Mathematical proof of external memory bridge cheat (FinalExp/GVA/RenaultDriver).";
                                                detections.push_back(d);
                                            }
                                        }
                                    }
                                    CloseHandle(hOwner);
                                }
                            }
                        }
                    }
                }
            }
        }

        return detections;
    }
}
