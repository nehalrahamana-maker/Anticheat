#include "VADScanner.hpp"
#include "SyscallEngine.hpp"
#include "PEParser.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

#ifndef MemorySectionName
#define MemorySectionName ((MEMORY_INFORMATION_CLASS)2)
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _MEMORY_SECTION_NAME {
    UNICODE_STRING SectionFileName;
} MEMORY_SECTION_NAME;

namespace VADScanner {

    static std::string ProtectionToString(DWORD protect) {
        switch (protect & 0xFF) {
        case PAGE_EXECUTE: return "PAGE_EXECUTE";
        case PAGE_EXECUTE_READ: return "PAGE_EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE (RWX)";
        case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
        case PAGE_READONLY: return "PAGE_READONLY";
        case PAGE_READWRITE: return "PAGE_READWRITE";
        default: return "PROTECT_0x" + std::to_string(protect);
        }
    }

    static std::string ToLower(const std::string& str) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower;
    }

    std::vector<VADDetection> ScanProcessVAD(DWORD pid, const std::string& procName) {
        std::vector<VADDetection> detections;

        HANDLE hProc = NULL;
        OBJECT_ATTRIBUTES_EX objAttr = { sizeof(OBJECT_ATTRIBUTES_EX) };
        CLIENT_ID_EX cid = { (HANDLE)(ULONG_PTR)pid, NULL };

        NTSTATUS st = SyscallEngine::DirectNtOpenProcess(
            &hProc,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            &objAttr,
            &cid
        );

        if (!NT_SUCCESS(st) || !hProc) return detections;

        // Build list of legitimate loaded module base addresses from Toolhelp32
        std::vector<ULONG_PTR> loadedBases;
        std::vector<std::string> loadedModuleNames;

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me;
            me.dwSize = sizeof(MODULEENTRY32W);
            if (Module32FirstW(hSnap, &me)) {
                do {
                    loadedBases.push_back((ULONG_PTR)me.modBaseAddr);
                    char nameBuf[MAX_PATH] = { 0 };
                    WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, nameBuf, MAX_PATH, NULL, NULL);
                    loadedModuleNames.push_back(ToLower(nameBuf));
                } while (Module32NextW(hSnap, &me));
            }
            CloseHandle(hSnap);
        }

        // Walk VAD tree from 0x10000 to 0x7FFFFFFF0000
        ULONG_PTR curAddr = 0x10000;
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T retLen = 0;

        while (NT_SUCCESS(SyscallEngine::DirectNtQueryVirtualMemory(
            hProc,
            (PVOID)curAddr,
            MemoryBasicInformationEx,
            &mbi,
            sizeof(mbi),
            &retLen
        ))) {
            if (mbi.State == MEM_COMMIT) {
                bool isExecutable = (mbi.Protect == PAGE_EXECUTE ||
                                     mbi.Protect == PAGE_EXECUTE_READ ||
                                     mbi.Protect == PAGE_EXECUTE_READWRITE ||
                                     mbi.Protect == PAGE_EXECUTE_WRITECOPY);

                if (isExecutable && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED)) {
                    // Query kernel VAD for physical disk backing via MemoryMappedFilenameInformationEx (Class 2)
                    BYTE sectionNameBuffer[sizeof(MEMORY_SECTION_NAME) + (MAX_PATH * sizeof(WCHAR))] = { 0 };
                    SIZE_T secRetLen = 0;
                    NTSTATUS secSt = SyscallEngine::DirectNtQueryVirtualMemory(
                        hProc,
                        mbi.BaseAddress,
                        MemoryMappedFilenameInformationEx,
                        sectionNameBuffer,
                        sizeof(sectionNameBuffer),
                        &secRetLen
                    );

                    std::string backingDevicePath = "";
                    if (NT_SUCCESS(secSt)) {
                        auto* pSec = reinterpret_cast<MEMORY_SECTION_NAME*>(sectionNameBuffer);
                        if (pSec->SectionFileName.Buffer && pSec->SectionFileName.Length > 0) {
                            char pathBuf[MAX_PATH] = { 0 };
                            WideCharToMultiByte(CP_UTF8, 0, pSec->SectionFileName.Buffer, pSec->SectionFileName.Length / sizeof(WCHAR), pathBuf, MAX_PATH, NULL, NULL);
                            backingDevicePath = pathBuf;
                        }
                    }

                    // Read first 256 bytes of region
                    std::vector<BYTE> sample(256, 0);
                    SIZE_T bytesRead = 0;
                    SyscallEngine::DirectNtReadVirtualMemory(hProc, mbi.BaseAddress, sample.data(), sample.size(), &bytesRead);

                    if (bytesRead >= 2) {
                        // Case A: MZ Header in MEM_PRIVATE or unbacked memory -> PEB-unlinked hidden DLL
                        if (sample[0] == 'M' && sample[1] == 'Z') {
                            VADDetection d;
                            d.ProcessId = pid;
                            d.ProcessName = procName;
                            d.BaseAddress = (ULONG_PTR)mbi.BaseAddress;
                            d.RegionSize = mbi.RegionSize;
                            d.MemoryType = (mbi.Type == MEM_PRIVATE) ? "MEM_PRIVATE" : "MEM_MAPPED";
                            d.MemoryProtection = ProtectionToString(mbi.Protect);
                            d.DetectionType = "PEB_UNLINKED_DLL (Hidden Module in VAD)";
                            d.Severity = "CRITICAL";
                            d.MemorySample = sample;
                            d.Description = "Unlinked PE module ('MZ' signature, size: " + std::to_string(mbi.RegionSize) + 
                                " bytes) discovered in " + d.MemoryType + " at 0x" + std::to_string((ULONG_PTR)mbi.BaseAddress) + 
                                ". Kernel VAD confirms module is unlinked from PEB list (stealth.cpp / manual-map).";
                            detections.push_back(d);
                        }
                        // Case B: Unbacked RWX (Read-Write-Execute) Shellcode stub
                        else if (mbi.Protect == PAGE_EXECUTE_READWRITE && backingDevicePath.empty() && mbi.RegionSize >= 4096) {
                            bool hasCode = false;
                            for (size_t k = 0; k < bytesRead; k++) {
                                if (sample[k] != 0x00) { hasCode = true; break; }
                            }

                            if (hasCode) {
                                VADDetection d;
                                d.ProcessId = pid;
                                d.ProcessName = procName;
                                d.BaseAddress = (ULONG_PTR)mbi.BaseAddress;
                                d.RegionSize = mbi.RegionSize;
                                d.MemoryType = "MEM_PRIVATE";
                                d.MemoryProtection = "PAGE_EXECUTE_READWRITE (RWX)";
                                d.DetectionType = "UNBACKED_RWX_SHELLCODE";
                                d.Severity = "CRITICAL";
                                d.MemorySample = sample;
                                d.Description = "Floating unbacked RWX memory allocation with active code at 0x" + 
                                    std::to_string((ULONG_PTR)mbi.BaseAddress) + " (Kernel VAD has no backing file). Injected shellcode / cheat thread stub.";
                                detections.push_back(d);
                            }
                        }
                    }
                }
            }

            curAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            if (curAddr >= 0x7FFFFFFF0000ULL || mbi.RegionSize == 0) break;
        }

        CloseHandle(hProc);
        return detections;
    }
}
