#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <map>

// NTSTATUS and standard NT definitions
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif

typedef struct _UNICODE_STRING_EX {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_EX, *PUNICODE_STRING_EX;

typedef struct _OBJECT_ATTRIBUTES_EX {
    ULONG               Length;
    HANDLE              RootDirectory;
    PUNICODE_STRING_EX  ObjectName;
    ULONG               Attributes;
    PVOID               SecurityDescriptor;
    PVOID               SecurityQualityOfService;
} OBJECT_ATTRIBUTES_EX, *POBJECT_ATTRIBUTES_EX;

typedef struct _CLIENT_ID_EX {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_EX, *PCLIENT_ID_EX;

typedef enum _MEMORY_INFORMATION_CLASS_EX {
    MemoryBasicInformationEx = 0,
    MemoryWorkingSetInformationEx = 1,
    MemoryMappedFilenameInformationEx = 2,
    MemoryRegionInformationEx = 3,
    MemoryWorkingSetExInformationEx = 4
} MEMORY_INFORMATION_CLASS_EX;

namespace SyscallEngine {

    struct SyscallEntry {
        std::string Name;
        DWORD SyscallNumber;
        PVOID SyscallRetAddress; // Address of 'syscall; ret' in ntdll
        PVOID ThunkAddress;      // Executable stub address
    };

    bool Initialize();
    void Cleanup();

    NTSTATUS DirectNtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES_EX ObjectAttributes,
        PCLIENT_ID_EX ClientId
    );

    NTSTATUS DirectNtReadVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferSize,
        PSIZE_T NumberOfBytesRead
    );

    NTSTATUS DirectNtQueryVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        MEMORY_INFORMATION_CLASS_EX MemoryInformationClass,
        PVOID MemoryInformation,
        SIZE_T MemoryInformationLength,
        PSIZE_T ReturnLength
    );

    NTSTATUS DirectNtQueryInformationProcess(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    const std::map<std::string, SyscallEntry>& GetResolvedSyscalls();
}
