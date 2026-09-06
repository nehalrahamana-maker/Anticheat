#include "AntiCheatDriver.h"

OB_PREOP_CALLBACK_STATUS AntiCheatProcessPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (g_ProtectedGamePid == 0) {
        return OB_PREOP_SUCCESS;
    }

    // Only inspect process objects
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE targetPid = PsGetProcessId(targetProcess);

    // If the target is our protected game (HD-Player.exe)
    if ((ULONG)(ULONG_PTR)targetPid == g_ProtectedGamePid) {
        PEPROCESS callingProcess = PsGetCurrentProcess();
        HANDLE callingPid = PsGetProcessId(callingProcess);

        // Allow game process to access itself, and allow our AntiCheat scanner
        if ((ULONG)(ULONG_PTR)callingPid != g_ProtectedGamePid) {
            ACCESS_MASK desiredAccess = 0;
            ACCESS_MASK strippedMask = (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | 
                                        PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_DUP_HANDLE);

            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
                if (desiredAccess & strippedMask) {
                    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~strippedMask;
                    g_StrippedHandlesCount++;
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                        "[🛡️ HANDLE STRIPPER] Stripped VM_READ/WRITE access to Game from External PID: %lu\n",
                        (ULONG)(ULONG_PTR)callingPid);
                }
            }
            else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
                if (desiredAccess & strippedMask) {
                    OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~strippedMask;
                    g_StrippedHandlesCount++;
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                        "[🛡️ HANDLE STRIPPER] Stripped duplicated VM handle to Game from External PID: %lu\n",
                        (ULONG)(ULONG_PTR)callingPid);
                }
            }
        }
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS InitializeHandleProtection(VOID) {
    OB_OPERATION_REGISTRATION opReg = { 0 };
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = AntiCheatProcessPreCallback;
    opReg.PostOperation = NULL;

    OB_CALLBACK_REGISTRATION cbReg = { 0 };
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.RegistrationContext = NULL;
    cbReg.OperationRegistration = &opReg;
    RtlInitUnicodeString(&cbReg.Altitude, L"321000"); // High security altitude

    NTSTATUS status = ObRegisterCallbacks(&cbReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[-] ObRegisterCallbacks failed: 0x%08X (Check test-signing / integrity)\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Ring 0 ObRegisterCallbacks Handle Stripper Active!\n");
    return STATUS_SUCCESS;
}

VOID CleanupHandleProtection(VOID) {
    if (g_ObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[*] ObRegisterCallbacks unregistered.\n");
    }
}
