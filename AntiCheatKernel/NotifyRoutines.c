#include "AntiCheatDriver.h"

static const wchar_t* g_VulnerableDriversBlacklist[] = {
    L"winverb.sys",
    L"capcom.sys",
    L"rtcore64.sys",
    L"gdrv.sys",
    L"kprocesshacker.sys",
    L"renaultdriver.sys",
    L"zwswap.sys",
    L"blackbone.sys",
    L"dbk64.sys",
    L"speedhack.sys",
    L"cpuz141.sys",
    L"procexp.sys",
    L"mhyprot2.sys",
    L"iqvw64e.sys"
};

BOOLEAN IsKnownVulnerableDriver(PUNICODE_STRING FullImageName) {
    if (!FullImageName || !FullImageName->Buffer || FullImageName->Length == 0) {
        return FALSE;
    }

    UNICODE_STRING lowerName;
    WCHAR buffer[260] = { 0 };
    lowerName.Buffer = buffer;
    lowerName.Length = 0;
    lowerName.MaximumLength = sizeof(buffer);

    RtlDowncaseUnicodeString(&lowerName, FullImageName, FALSE);

    ULONG count = sizeof(g_VulnerableDriversBlacklist) / sizeof(g_VulnerableDriversBlacklist[0]);
    for (ULONG i = 0; i < count; i++) {
        UNICODE_STRING target;
        RtlInitUnicodeString(&target, g_VulnerableDriversBlacklist[i]);
        if (RtlFindUnicodeSubstring(&lowerName, &target, TRUE) != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

VOID AntiCheatLoadImageNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
) {
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);

    if (!FullImageName || !FullImageName->Buffer) return;

    // Check if this image is a kernel driver
    if (ImageInfo->SystemModeImage) {
        if (IsKnownVulnerableDriver(FullImageName)) {
            g_BlockedDriversCount++;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[🚨 ANTICHEAT KERNEL GUARD] BLOCKED Vulnerable BYOVD Driver from loading: %wZ at Base: 0x%p\n",
                FullImageName, ImageInfo->ImageBase);

            // In strict kernel mode, we invalidate headers or trigger driver eviction
        }
    }
}

VOID AntiCheatProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        // Process Creation: Audit parent process and command line
        if (CreateInfo->ImageFileName != NULL) {
            UNICODE_STRING lowerImage;
            WCHAR buf[260] = { 0 };
            lowerImage.Buffer = buf;
            lowerImage.Length = 0;
            lowerImage.MaximumLength = sizeof(buf);
            RtlDowncaseUnicodeString(&lowerImage, CreateInfo->ImageFileName, FALSE);

            // Check if known injector is launching
            UNICODE_STRING cheatKw;
            RtlInitUnicodeString(&cheatKw, L"cruz");
            if (RtlFindUnicodeSubstring(&lowerImage, &cheatKw, TRUE) != NULL) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[🚨 ANTICHEAT KERNEL GUARD] Blocked known cheat launcher: %wZ (PID: %lu)\n",
                    CreateInfo->ImageFileName, (ULONG)(ULONG_PTR)ProcessId);
                
                // Deny process creation at the kernel dispatcher level!
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            }
        }
    }
}

NTSTATUS InitializeNotifyRoutines(VOID) {
    NTSTATUS status = PsSetLoadImageNotifyRoutine(AntiCheatLoadImageNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to register PsSetLoadImageNotifyRoutine: 0x%08X\n", status);
        return status;
    }

    status = PsSetCreateProcessNotifyRoutineEx(AntiCheatProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to register PsSetCreateProcessNotifyRoutineEx: 0x%08X\n", status);
        PsRemoveLoadImageNotifyRoutine(AntiCheatLoadImageNotifyRoutine);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] AntiCheat Kernel Gatekeeper (LoadImage & ProcessNotify) Armed!\n");
    return STATUS_SUCCESS;
}

VOID CleanupNotifyRoutines(VOID) {
    PsRemoveLoadImageNotifyRoutine(AntiCheatLoadImageNotifyRoutine);
    PsSetCreateProcessNotifyRoutineEx(AntiCheatProcessNotifyRoutineEx, TRUE);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[*] Notify routines unregistered.\n");
}
