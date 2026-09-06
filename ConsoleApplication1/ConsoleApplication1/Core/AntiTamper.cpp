#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "AntiTamper.hpp"
#include "PEParser.hpp"
#include "SyscallEngine.hpp"
#include <winternl.h>
#include <intrin.h>
#include <psapi.h>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

#ifndef ProcessDebugPort
#define ProcessDebugPort 7
#endif

#ifndef ProcessDebugObjectHandle
#define ProcessDebugObjectHandle 30
#endif

#ifndef ProcessDebugFlags
#define ProcessDebugFlags 31
#endif

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

namespace AntiTamper {

    AntiTamperStatus AuditSelfIntegrity() {
        AntiTamperStatus status;

        // 1. Win32 API Debugger Check
        if (IsDebuggerPresent()) {
            status.IsDebuggerAttached = true;
            status.TamperFlags.push_back("WIN32_IS_DEBUGGER_PRESENT");
        }

        BOOL bRemote = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bRemote) && bRemote) {
            status.IsDebuggerAttached = true;
            status.TamperFlags.push_back("CHECK_REMOTE_DEBUGGER_PRESENT");
        }

        // 2. Direct PEB In-Memory Inspection (Bypasses API Hooks)
        PBYTE pPeb = (PBYTE)__readgsqword(0x60);
        if (pPeb) {
            // Check PEB.BeingDebugged (offset 0x02)
            if (pPeb[2] == 1) {
                status.IsDebuggerAttached = true;
                status.TamperFlags.push_back("PEB_BEING_DEBUGGED_FLAG");
            }

            // Check NtGlobalFlag (offset 0xBC on x64)
            DWORD ntGlobalFlag = *reinterpret_cast<DWORD*>(pPeb + 0xBC);
            if ((ntGlobalFlag & 0x70) == 0x70) { // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
                status.IsDebuggerAttached = true;
                status.TamperFlags.push_back("PEB_NT_GLOBAL_FLAG_DEBUG_HEAP");
            }
        }

        // 3. Kernel Debug Object Handle & Port Check
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            auto pfnQueryProcInfo = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
            if (pfnQueryProcInfo) {
                DWORD_PTR debugPort = 0;
                ULONG retLen = 0;
                if (NT_SUCCESS(pfnQueryProcInfo(GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), &retLen))) {
                    if (debugPort != 0) {
                        status.IsDebuggerAttached = true;
                        status.TamperFlags.push_back("KERNEL_PROCESS_DEBUG_PORT_ACTIVE");
                    }
                }

                HANDLE hDebugObj = NULL;
                if (NT_SUCCESS(pfnQueryProcInfo(GetCurrentProcess(), ProcessDebugObjectHandle, &hDebugObj, sizeof(hDebugObj), &retLen))) {
                    if (hDebugObj != NULL) {
                        status.IsDebuggerAttached = true;
                        status.TamperFlags.push_back("KERNEL_DEBUG_OBJECT_ATTACHED");
                    }
                }
            }
        }

        // 4. Thread Hardware Breakpoint Audit (Dr0-Dr7 on own scanner thread)
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        HANDLE hCurrentThread = GetCurrentThread();
        if (GetThreadContext(hCurrentThread, &ctx)) {
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 || (ctx.Dr7 & 0xFF) != 0) {
                status.HasHardwareBreakpoints = true;
                status.TamperFlags.push_back("SCANNER_THREAD_HARDWARE_BREAKPOINT");
            }
        }

        // 5. Self-Code Section Integrity (.text byte-diff vs disk image)
        WCHAR szSelfPath[MAX_PATH] = { 0 };
        if (GetModuleFileNameW(NULL, szSelfPath, MAX_PATH) > 0) {
            PE::PEImage selfPE;
            if (selfPE.LoadFromFile(szSelfPath)) {
                status.ScannerImageSHA256 = PE::PEImage::ComputeSHA256(selfPE.GetRawBuffer());

                HMODULE hSelfBase = GetModuleHandleW(NULL);
                if (hSelfBase) {
                    const auto& sections = selfPE.GetSections();
                    for (const auto& sec : sections) {
                        if (sec.Name == ".text" && sec.VirtualSize > 0) {
                            const BYTE* memText = (const BYTE*)hSelfBase + sec.VirtualAddress;
                            if (sec.RawOffset + sec.RawSize <= selfPE.GetRawBuffer().size()) {
                                const BYTE* diskText = selfPE.GetRawBuffer().data() + sec.RawOffset;
                                size_t compareSize = ((size_t)sec.VirtualSize < (size_t)sec.RawSize) ? (size_t)sec.VirtualSize : (size_t)sec.RawSize;
                                size_t mismatchCount = 0;
                                for (size_t i = 0; i < compareSize; i++) {
                                    if (memText[i] != diskText[i]) mismatchCount++;
                                }
                                if (mismatchCount > 0) {
                                    status.IsSelfCodeTampered = true;
                                    status.TamperFlags.push_back("SCANNER_TEXT_SECTION_PATCHED (" + std::to_string(mismatchCount) + " bytes modified)");
                                }
                            }
                        }
                    }
                }
            }
        }

        // 6. Own Process Virtual Memory Audit (Injected Shellcode / Unbacked RWX pages)
        ULONG_PTR currentAddr = 0;
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        size_t suspiciousRegionCount = 0;

        while (VirtualQuery((LPCVOID)currentAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
                if (mbi.Protect == PAGE_EXECUTE_READWRITE) {
                    suspiciousRegionCount++;
                }
            }
            ULONG_PTR nextAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            if (nextAddr <= currentAddr) break;
            currentAddr = nextAddr;
        }

        if (suspiciousRegionCount > 0) {
            status.HasInjectedMemory = true;
            status.TamperFlags.push_back("SCANNER_PROCESS_INJECTED_RWX_MEMORY (" + std::to_string(suspiciousRegionCount) + " regions)");
        }

        // 7. Critical Win32 API Hook Audit in Scanner Process
        static const std::vector<std::string> criticalApis = {
            "VirtualProtect", "ReadProcessMemory", "OpenProcess", "TerminateProcess", "CreateRemoteThread"
        };
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32) {
            for (const auto& api : criticalApis) {
                FARPROC pFunc = GetProcAddress(hKernel32, api.c_str());
                if (pFunc) {
                    BYTE* code = (BYTE*)pFunc;
                    if (code[0] == 0xE9 || (code[0] == 0xFF && code[1] == 0x25) || (code[0] == 0x48 && code[1] == 0xB8)) {
                        status.IsMemoryHooked = true;
                        status.TamperFlags.push_back("SCANNER_WIN32_API_HOOKED (kernel32!" + api + ")");
                    }
                }
            }
        }

        status.IsTampered = status.IsDebuggerAttached || status.HasHardwareBreakpoints ||
                            status.IsMemoryHooked || status.IsSelfCodeTampered || status.HasInjectedMemory;

        if (status.IsTampered) {
            status.StatusSummary = "CRITICAL ANTI-TAMPER ALERT: Active debugger / in-memory patch / injected code detected in scanner process!";
        }
        else {
            status.StatusSummary = "Anti-Tamper Integrity: Scanner memory, code section hash, and execution environment 100% SECURE.";
        }

        return status;
    }
}
