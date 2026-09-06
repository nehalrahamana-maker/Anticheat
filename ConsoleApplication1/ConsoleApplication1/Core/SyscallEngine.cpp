#include "SyscallEngine.hpp"
#include <iostream>
#include <fstream>
#include <vector>

namespace SyscallEngine {

    static std::map<std::string, SyscallEntry> g_Syscalls;
    static PVOID g_ThunkPool = nullptr;
    static SIZE_T g_ThunkPoolSize = 0;
    static PVOID g_SyscallRetGadget = nullptr;

    static PVOID FindSyscallRetGadget(HMODULE hNtdll) {
        if (!hNtdll) return nullptr;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (memcmp(section[i].Name, ".text", 5) == 0) {
                BYTE* start = (BYTE*)hNtdll + section[i].VirtualAddress;
                SIZE_T size = section[i].Misc.VirtualSize;

                for (SIZE_T j = 0; j < size - 3; j++) {
                    if (start[j] == 0x0F && start[j + 1] == 0x05 && start[j + 2] == 0xC3) {
                        return (PVOID)(start + j);
                    }
                }
            }
        }
        return nullptr;
    }

    static bool ExtractSyscallNumbersFromDisk(const std::vector<std::string>& funcNames) {
        std::ifstream file("C:\\Windows\\System32\\ntdll.dll", std::ios::binary);
        if (!file) return false;

        std::vector<BYTE> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) return false;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buffer.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        DWORD exportDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD exportDirSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exportDirRVA || !exportDirSize) return false;

        auto RvaToOffset = [&](DWORD rva) -> DWORD {
            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
                    return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
                }
            }
            return 0;
        };

        DWORD exportOffset = RvaToOffset(exportDirRVA);
        if (!exportOffset || exportOffset >= buffer.size()) return false;

        PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(buffer.data() + exportOffset);
        DWORD* names = (DWORD*)(buffer.data() + RvaToOffset(exp->AddressOfNames));
        WORD* ordinals = (WORD*)(buffer.data() + RvaToOffset(exp->AddressOfNameOrdinals));
        DWORD* functions = (DWORD*)(buffer.data() + RvaToOffset(exp->AddressOfFunctions));

        for (const auto& targetName : funcNames) {
            for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                DWORD nameOffset = RvaToOffset(names[i]);
                if (!nameOffset || nameOffset >= buffer.size()) continue;

                const char* funcName = (const char*)(buffer.data() + nameOffset);
                if (targetName == funcName) {
                    WORD ord = ordinals[i];
                    DWORD funcRva = functions[ord];
                    DWORD funcOffset = RvaToOffset(funcRva);

                    if (funcOffset && funcOffset + 32 <= buffer.size()) {
                        BYTE* code = buffer.data() + funcOffset;
                        for (int k = 0; k < 20; k++) {
                            if (code[k] == 0xB8) {
                                DWORD ssn = *(DWORD*)&code[k + 1];
                                SyscallEntry entry;
                                entry.Name = targetName;
                                entry.SyscallNumber = ssn;
                                entry.SyscallRetAddress = g_SyscallRetGadget;
                                entry.ThunkAddress = nullptr;
                                g_Syscalls[targetName] = entry;
                                break;
                            }
                        }
                    }
                    break;
                }
            }
        }
        return true;
    }

    bool Initialize() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            hNtdll = LoadLibraryW(L"ntdll.dll");
        }
        if (!hNtdll) return false;

        g_SyscallRetGadget = FindSyscallRetGadget(hNtdll);
        if (!g_SyscallRetGadget) {
            return false;
        }

        std::vector<std::string> requiredSyscalls = {
            "NtOpenProcess",
            "NtReadVirtualMemory",
            "NtQueryVirtualMemory",
            "NtQueryInformationProcess",
            "NtOpenKeyEx",
            "NtEnumerateKey",
            "NtQueryValueKey"
        };

        if (!ExtractSyscallNumbersFromDisk(requiredSyscalls)) {
            return false;
        }

        const SIZE_T THUNK_SIZE = 32;
        g_ThunkPoolSize = g_Syscalls.size() * THUNK_SIZE;
        g_ThunkPool = VirtualAlloc(nullptr, g_ThunkPoolSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!g_ThunkPool) return false;

        BYTE* curThunk = (BYTE*)g_ThunkPool;
        for (auto& pair : g_Syscalls) {
            SyscallEntry& entry = pair.second;
            entry.ThunkAddress = curThunk;

            BYTE stub[] = {
                0x49, 0x89, 0xCA,                               // mov r10, rcx
                0xB8, 0x00, 0x00, 0x00, 0x00,                   // mov eax, <ssn>
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp qword ptr [rip + 0]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // target address
            };

            *(DWORD*)&stub[4] = entry.SyscallNumber;
            *(PVOID*)&stub[14] = entry.SyscallRetAddress;

            memcpy(curThunk, stub, sizeof(stub));
            curThunk += THUNK_SIZE;
        }

        DWORD oldProtect = 0;
        VirtualProtect(g_ThunkPool, g_ThunkPoolSize, PAGE_EXECUTE_READ, &oldProtect);
        return true;
    }

    void Cleanup() {
        if (g_ThunkPool) {
            VirtualFree(g_ThunkPool, 0, MEM_RELEASE);
            g_ThunkPool = nullptr;
        }
        g_Syscalls.clear();
    }

    const std::map<std::string, SyscallEntry>& GetResolvedSyscalls() {
        return g_Syscalls;
    }

    typedef NTSTATUS(NTAPI* pfnNtOpenProcess)(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES_EX ObjectAttributes,
        PCLIENT_ID_EX ClientId
    );

    typedef NTSTATUS(NTAPI* pfnNtReadVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferSize,
        PSIZE_T NumberOfBytesRead
    );

    typedef NTSTATUS(NTAPI* pfnNtQueryVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        MEMORY_INFORMATION_CLASS_EX MemoryInformationClass,
        PVOID MemoryInformation,
        SIZE_T MemoryInformationLength,
        PSIZE_T ReturnLength
    );

    typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    NTSTATUS DirectNtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES_EX ObjectAttributes,
        PCLIENT_ID_EX ClientId
    ) {
        auto it = g_Syscalls.find("NtOpenProcess");
        if (it != g_Syscalls.end() && it->second.ThunkAddress) {
            return ((pfnNtOpenProcess)it->second.ThunkAddress)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
        }
        typedef NTSTATUS(NTAPI* pfn)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
        static pfn fallback = (pfn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess");
        if (fallback) return fallback(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
        return STATUS_NOT_IMPLEMENTED;
    }

    NTSTATUS DirectNtReadVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferSize,
        PSIZE_T NumberOfBytesRead
    ) {
        auto it = g_Syscalls.find("NtReadVirtualMemory");
        if (it != g_Syscalls.end() && it->second.ThunkAddress) {
            return ((pfnNtReadVirtualMemory)it->second.ThunkAddress)(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
        }
        typedef NTSTATUS(NTAPI* pfn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        static pfn fallback = (pfn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReadVirtualMemory");
        if (fallback) return fallback(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
        return STATUS_NOT_IMPLEMENTED;
    }

    NTSTATUS DirectNtQueryVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        MEMORY_INFORMATION_CLASS_EX MemoryInformationClass,
        PVOID MemoryInformation,
        SIZE_T MemoryInformationLength,
        PSIZE_T ReturnLength
    ) {
        auto it = g_Syscalls.find("NtQueryVirtualMemory");
        if (it != g_Syscalls.end() && it->second.ThunkAddress) {
            return ((pfnNtQueryVirtualMemory)it->second.ThunkAddress)(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
        }
        typedef NTSTATUS(NTAPI* pfn)(HANDLE, PVOID, int, PVOID, SIZE_T, PSIZE_T);
        static pfn fallback = (pfn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryVirtualMemory");
        if (fallback) return fallback(ProcessHandle, BaseAddress, (int)MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
        return STATUS_NOT_IMPLEMENTED;
    }

    NTSTATUS DirectNtQueryInformationProcess(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    ) {
        auto it = g_Syscalls.find("NtQueryInformationProcess");
        if (it != g_Syscalls.end() && it->second.ThunkAddress) {
            return ((pfnNtQueryInformationProcess)it->second.ThunkAddress)(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
        }
        typedef NTSTATUS(NTAPI* pfn)(HANDLE, DWORD, PVOID, ULONG, PULONG);
        static pfn fallback = (pfn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
        if (fallback) return fallback(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
        return STATUS_NOT_IMPLEMENTED;
    }
}
