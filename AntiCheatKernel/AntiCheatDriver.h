#pragma once
#include <ntddk.h>
#include <ntstrsafe.h>

#define DEVICE_NAME L"\\Device\\AntiCheatGuard"
#define SYMLINK_NAME L"\\DosDevices\\AntiCheatGuard"

// IOCTL Codes
#define IOCTL_AC_REGISTER_GAME_PID   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AC_GET_DRIVER_STATUS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AC_AUDIT_KERNEL_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _AC_REGISTER_PID_REQUEST {
    ULONG ProcessId;
    BOOLEAN EnableHandleProtection;
    BOOLEAN EnableMemoryIntegrity;
} AC_REGISTER_PID_REQUEST, *PAC_REGISTER_PID_REQUEST;

typedef struct _AC_DRIVER_STATUS_RESPONSE {
    BOOLEAN CallbacksActive;
    BOOLEAN ObRegisterActive;
    ULONG BlockedDriversCount;
    ULONG StrippedHandlesCount;
} AC_DRIVER_STATUS_RESPONSE, *PAC_DRIVER_STATUS_RESPONSE;

// Global state
extern PDEVICE_OBJECT g_DeviceObject;
extern ULONG g_ProtectedGamePid;
extern PVOID g_ObRegistrationHandle;
extern ULONG g_BlockedDriversCount;
extern ULONG g_StrippedHandlesCount;

// Function Prototypes
NTSTATUS InitializeNotifyRoutines(VOID);
VOID CleanupNotifyRoutines(VOID);

NTSTATUS InitializeHandleProtection(VOID);
VOID CleanupHandleProtection(VOID);

NTSTATUS AuditKernelDriverMemory(VOID);
BOOLEAN IsKnownVulnerableDriver(PUNICODE_STRING FullImageName);
