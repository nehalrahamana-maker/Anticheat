#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "ProcessHollowingScanner.hpp"
#include "SyscallEngine.hpp"
#include "PEParser.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <winternl.h>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

#ifndef ProcessBasicInformation
#define ProcessBasicInformation 0
#endif

typedef struct _PROCESS_BASIC_INFORMATION_EX {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_EX;

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

namespace ProcessHollowingScanner {

    static std::string WideToNarrow(const std::wstring& ws) {
        if (ws.empty()) return {};
        char buf[MAX_PATH * 2] = {};
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, buf, sizeof(buf), NULL, NULL);
        return buf;
    }

    std::vector<ProcessHollowingDetection> ScanProcessHollowing(DWORD pid, const std::string& procName) {
        std::vector<ProcessHollowingDetection> detections;

        if (pid == 0 || pid == 4) return detections;

        // Skip protected system processes if access denied
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProc) return detections;

        WCHAR diskPath[MAX_PATH] = { 0 };
        DWORD dwPathSize = MAX_PATH;
        if (!QueryFullProcessImageNameW(hProc, 0, diskPath, &dwPathSize)) {
            CloseHandle(hProc);
            return detections;
        }

        // Retrieve PEB address to find the ImageBaseAddress
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            CloseHandle(hProc);
            return detections;
        }

        auto pfnQueryProc = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!pfnQueryProc) {
            CloseHandle(hProc);
            return detections;
        }

        PROCESS_BASIC_INFORMATION_EX pbi = { 0 };
        ULONG retLen = 0;
        NTSTATUS status = pfnQueryProc(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
        if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) {
            CloseHandle(hProc);
            return detections;
        }

        // In 64-bit Windows, PEB.ImageBaseAddress is at offset 0x10
        ULONG_PTR pebBase = (ULONG_PTR)pbi.PebBaseAddress;
        ULONG_PTR imageBase = 0;
        SIZE_T bytesRead = 0;
        NTSTATUS memStatus = SyscallEngine::DirectNtReadVirtualMemory(
            hProc,
            (PVOID)(pebBase + 0x10),
            &imageBase,
            sizeof(imageBase),
            &bytesRead
        );

        if (!NT_SUCCESS(memStatus) || !imageBase) {
            CloseHandle(hProc);
            return detections;
        }

        // 1. Check Virtual Memory Attributes of ImageBaseAddress (Doppelganging / Manual Map Hunter)
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        SIZE_T mbiRet = 0;
        if (NT_SUCCESS(SyscallEngine::DirectNtQueryVirtualMemory(hProc, (PVOID)imageBase, MemoryBasicInformationEx, &mbi, sizeof(mbi), &mbiRet))) {
            if (mbi.Type == MEM_PRIVATE) {
                ProcessHollowingDetection det;
                det.ProcessId = pid;
                det.ProcessName = procName;
                det.ImageBaseAddress = imageBase;
                det.ExpectedDiskPath = diskPath;
                det.HollowingTechnique = "PROCESS_DOPPELGANGING_MEM_PRIVATE_IMAGE";
                det.Severity = "CRITICAL";
                det.Description = "Process main ImageBaseAddress (0x" +
                    [&]{ char tmp[32]; sprintf_s(tmp, "%llX", (unsigned long long)imageBase); return std::string(tmp); }() +
                    ") is MEM_PRIVATE (unbacked heap/virtual memory) instead of MEM_IMAGE! Confirmed Process Doppelganging / Manual Map Injection.";
                detections.push_back(det);
            }
            else if (mbi.Type == MEM_MAPPED) {
                ProcessHollowingDetection det;
                det.ProcessId = pid;
                det.ProcessName = procName;
                det.ImageBaseAddress = imageBase;
                det.ExpectedDiskPath = diskPath;
                det.HollowingTechnique = "PROCESS_GHOSTING_MEM_MAPPED_IMAGE";
                det.Severity = "CRITICAL";
                det.Description = "Process main ImageBaseAddress is backed by an anonymous MEM_MAPPED section. Process Ghosting / Transacted Section injection!";
                detections.push_back(det);
            }
        }

        // 2. Read in-memory DOS + NT headers at ImageBaseAddress
        BYTE inMemoryHeader[0x1000] = { 0 };
        SIZE_T hdrRead = 0;
        SyscallEngine::DirectNtReadVirtualMemory(hProc, (PVOID)imageBase, inMemoryHeader, sizeof(inMemoryHeader), &hdrRead);

        if (hdrRead >= sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) {
            PIMAGE_DOS_HEADER pDosMem = (PIMAGE_DOS_HEADER)inMemoryHeader;
            if (pDosMem->e_magic == IMAGE_DOS_SIGNATURE && pDosMem->e_lfanew < (LONG)(sizeof(inMemoryHeader) - sizeof(IMAGE_NT_HEADERS64))) {
                PIMAGE_NT_HEADERS64 pNtMem = (PIMAGE_NT_HEADERS64)(inMemoryHeader + pDosMem->e_lfanew);
                if (pNtMem->Signature == IMAGE_NT_SIGNATURE) {
                    ULONG_PTR memEntryPoint = pNtMem->OptionalHeader.AddressOfEntryPoint;
                    DWORD memNumSections = pNtMem->FileHeader.NumberOfSections;
                    DWORD memSizeOfImage = pNtMem->OptionalHeader.SizeOfImage;

                    // 3. Load clean executable from disk and compare PE structure
                    PE::PEImage diskPE;
                    if (diskPE.LoadFromFile(diskPath)) {
                        const auto& diskBuffer = diskPE.GetRawBuffer();
                        if (diskBuffer.size() >= sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) {
                            PIMAGE_DOS_HEADER pDosDisk = (PIMAGE_DOS_HEADER)diskBuffer.data();
                            if (pDosDisk->e_magic == IMAGE_DOS_SIGNATURE && pDosDisk->e_lfanew < (LONG)(diskBuffer.size() - sizeof(IMAGE_NT_HEADERS64))) {
                                PIMAGE_NT_HEADERS64 pNtDisk = (PIMAGE_NT_HEADERS64)(diskBuffer.data() + pDosDisk->e_lfanew);
                                if (pNtDisk->Signature == IMAGE_NT_SIGNATURE) {
                                    ULONG_PTR diskEntryPoint = pNtDisk->OptionalHeader.AddressOfEntryPoint;
                                    DWORD diskNumSections = pNtDisk->FileHeader.NumberOfSections;
                                    DWORD diskSizeOfImage = pNtDisk->OptionalHeader.SizeOfImage;

                                    // Check A: EntryPoint Mismatch
                                    if (memEntryPoint != diskEntryPoint) {
                                        ProcessHollowingDetection det;
                                        det.ProcessId = pid;
                                        det.ProcessName = procName;
                                        det.ImageBaseAddress = imageBase;
                                        det.EntryPointInMemory = imageBase + memEntryPoint;
                                        det.EntryPointOnDisk = diskEntryPoint;
                                        det.ExpectedDiskPath = diskPath;
                                        det.HollowingTechnique = "PROCESS_HOLLOWING_ENTRYPOINT_MISMATCH";
                                        det.Severity = "CRITICAL";
                                        det.Description = "Process Hollowing: AddressOfEntryPoint in memory (0x" +
                                            [&]{ char tmp[32]; sprintf_s(tmp, "%llX", (unsigned long long)(imageBase + memEntryPoint)); return std::string(tmp); }() +
                                            ") does not match disk PE (0x" +
                                            [&]{ char tmp[32]; sprintf_s(tmp, "%llX", (unsigned long long)diskEntryPoint); return std::string(tmp); }() +
                                            ")! Payload executed from hollowed section.";
                                        detections.push_back(det);
                                    }

                                    // Check B: Section count or SizeOfImage replacement
                                    if (memNumSections != diskNumSections || memSizeOfImage != diskSizeOfImage) {
                                        ProcessHollowingDetection det;
                                        det.ProcessId = pid;
                                        det.ProcessName = procName;
                                        det.ImageBaseAddress = imageBase;
                                        det.ExpectedDiskPath = diskPath;
                                        det.HollowingTechnique = "PE_HEADER_OVERWRITE_DETECTED";
                                        det.Severity = "CRITICAL";
                                        det.Description = "In-memory PE Header structure altered (Sections: " +
                                            std::to_string(memNumSections) + " vs disk " + std::to_string(diskNumSections) +
                                            ", SizeOfImage: 0x" +
                                            [&]{ char tmp[16]; sprintf_s(tmp, "%X", memSizeOfImage); return std::string(tmp); }() +
                                            " vs disk 0x" +
                                            [&]{ char tmp[16]; sprintf_s(tmp, "%X", diskSizeOfImage); return std::string(tmp); }() +
                                            "). Complete PE Replacement!";
                                        detections.push_back(det);
                                    }

                                    // Check C: EntryPoint points outside valid code section bounds
                                    bool isEpInsideValidSection = false;
                                    const auto& sections = diskPE.GetSections();
                                    for (const auto& sec : sections) {
                                        if (memEntryPoint >= sec.VirtualAddress &&
                                            memEntryPoint < sec.VirtualAddress + sec.VirtualSize) {
                                            isEpInsideValidSection = true;
                                            break;
                                        }
                                    }
                                    if (!isEpInsideValidSection && memEntryPoint != 0) {
                                        ProcessHollowingDetection det;
                                        det.ProcessId = pid;
                                        det.ProcessName = procName;
                                        det.ImageBaseAddress = imageBase;
                                        det.EntryPointInMemory = imageBase + memEntryPoint;
                                        det.ExpectedDiskPath = diskPath;
                                        det.HollowingTechnique = "ENTRYPOINT_OUT_OF_BOUNDS_EXECUTION";
                                        det.Severity = "CRITICAL";
                                        det.Description = "In-memory EntryPoint (0x" +
                                            [&]{ char tmp[32]; sprintf_s(tmp, "%llX", (unsigned long long)(imageBase + memEntryPoint)); return std::string(tmp); }() +
                                            ") points outside all valid PE sections!";
                                        detections.push_back(det);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        CloseHandle(hProc);
        return detections;
    }

    std::vector<ProcessHollowingDetection> ScanAllProcessesHollowing() {
        std::vector<ProcessHollowingDetection> all;

        DWORD pids[2048] = {};
        DWORD needed = 0;
        if (!EnumProcesses(pids, sizeof(pids), &needed)) return all;

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

            auto procDets = ScanProcessHollowing(pid, nameBuf);
            all.insert(all.end(), procDets.begin(), procDets.end());
        }

        return all;
    }

} // namespace ProcessHollowingScanner
