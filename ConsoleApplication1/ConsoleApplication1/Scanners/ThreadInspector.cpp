#include "ThreadInspector.hpp"
#include "SyscallEngine.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9
#endif

typedef NTSTATUS(NTAPI* pfnNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

namespace ThreadInspector {

    std::vector<ThreadDetection> InspectProcessThreads(DWORD pid, const std::string& procName) {
        std::vector<ThreadDetection> detections;

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return detections;

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        auto pfnQueryInfoThread = hNtdll ? (pfnNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread") : nullptr;

        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    HANDLE hThread = OpenThread(
                        THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                        FALSE,
                        te.th32ThreadID
                    );

                    if (hThread) {
                        // Atomic snapshot: suspend thread for ~1ms to guarantee register consistency
                        SuspendThread(hThread);

                        // 1. Audit Debug Registers (Dr0-Dr7)
                        CONTEXT ctx = { 0 };
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;

                        if (GetThreadContext(hThread, &ctx)) {
                            // Check Dr7 enable flags (bits 0, 2, 4, 6) or non-zero Dr0-Dr3
                            bool hasActiveHwbp = (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 || ((ctx.Dr7 & 0xFF) != 0));

                            if (hasActiveHwbp) {
                                ThreadDetection d;
                                d.ProcessId = pid;
                                d.ProcessName = procName;
                                d.ThreadId = te.th32ThreadID;
                                d.CurrentRip = ctx.Rip;
                                d.DetectionType = "HARDWARE_BREAKPOINT_HOOK (Dr0-Dr7 Active)";
                                d.Severity = "CRITICAL";
                                d.Description = "Hardware Breakpoint (DR0=0x" + std::to_string(ctx.Dr0) + 
                                    ", DR1=0x" + std::to_string(ctx.Dr1) + 
                                    ", DR2=0x" + std::to_string(ctx.Dr2) + 
                                    ", DR3=0x" + std::to_string(ctx.Dr3) + 
                                    ", DR7=0x" + std::to_string(ctx.Dr7) + ") active on TID " + std::to_string(te.th32ThreadID) + 
                                    ". Defeats hvci_hook.h / page-less VEH execution interception.";
                                detections.push_back(d);
                            }

                            // 2. Audit Ghost Threads & Rip pointer
                            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                            if (hProc) {
                                char mappedName[MAX_PATH] = { 0 };
                                DWORD mappedLen = GetMappedFileNameA(hProc, (PVOID)ctx.Rip, mappedName, MAX_PATH);

                                MEMORY_BASIC_INFORMATION mbi = { 0 };
                                if (VirtualQueryEx(hProc, (PVOID)ctx.Rip, &mbi, sizeof(mbi))) {
                                    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && 
                                        (mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
                                        
                                        ThreadDetection d;
                                        d.ProcessId = pid;
                                        d.ProcessName = procName;
                                        d.ThreadId = te.th32ThreadID;
                                        d.CurrentRip = ctx.Rip;
                                        d.DetectionType = "GHOST_THREAD_APC_HIJACK (Unbacked RIP)";
                                        d.Severity = "CRITICAL";
                                        d.Description = "Thread TID " + std::to_string(te.th32ThreadID) + 
                                            " executing in unbacked private memory at RIP 0x" + std::to_string(ctx.Rip) + 
                                            ". Defeats ghost_thread.h / APC start address redirection.";
                                        detections.push_back(d);
                                    }
                                }
                                CloseHandle(hProc);
                            }
                        }

                        // 3. Query Win32 Start Address
                        if (pfnQueryInfoThread) {
                            ULONG_PTR startAddr = 0;
                            ULONG retLen = 0;
                            if (NT_SUCCESS(pfnQueryInfoThread(hThread, ThreadQuerySetWin32StartAddress, &startAddr, sizeof(startAddr), &retLen))) {
                                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                                if (hProc) {
                                    char mappedName[MAX_PATH] = { 0 };
                                    DWORD mappedLen = GetMappedFileNameA(hProc, (PVOID)startAddr, mappedName, MAX_PATH);
                                    if (mappedLen == 0 && startAddr > 0x10000) {
                                        MEMORY_BASIC_INFORMATION mbi = { 0 };
                                        if (VirtualQueryEx(hProc, (PVOID)startAddr, &mbi, sizeof(mbi))) {
                                            if (mbi.Type == MEM_PRIVATE && (mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
                                                ThreadDetection d;
                                                d.ProcessId = pid;
                                                d.ProcessName = procName;
                                                d.ThreadId = te.th32ThreadID;
                                                d.StartAddress = startAddr;
                                                d.DetectionType = "UNBACKED_THREAD_START_ADDRESS";
                                                d.Severity = "HIGH";
                                                d.Description = "Thread TID " + std::to_string(te.th32ThreadID) + " start address (0x" + 
                                                    std::to_string(startAddr) + ") points to unbacked private memory.";
                                                detections.push_back(d);
                                            }
                                        }
                                    }
                                    CloseHandle(hProc);
                                }
                            }
                        }

                        // Resume thread immediately
                        ResumeThread(hThread);
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnap, &te));
        }

        CloseHandle(hSnap);
        return detections;
    }
}
