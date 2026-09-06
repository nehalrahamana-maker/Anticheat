#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace EnforcementEngine {

    struct SystemHWIDInfo {
        std::string MotherboardUUID;
        std::string MotherboardSerial;
        std::string DiskSerial;
        std::string GPUDescription;
        std::string GPUPciId;
        std::string CPUBrand;
        std::string CPUProcessorId;
        std::string CompositeHWID; // e.g. "HWID-8F92-A3B1-4C5D-9E02"
        std::string RawHWIDHash;   // SHA-256 string
    };

    struct EnforcementConfig {
        bool AutoKillEnabled = false;
        bool StrictHVCIRequired = false;
        std::string BanWebhookUrl = "";
        std::string ServerApiKey = "";
    };

    struct EnforcementResult {
        bool TerminatedGame = false;
        bool TerminatedCheat = false;
        bool TelemetrySent = false;
        DWORD TerminatedPid = 0;
        SystemHWIDInfo TargetHWID;
        std::string ActionSummary;
    };

    // Extract hardware identifiers and compute cryptographic hardware ban fingerprint
    SystemHWIDInfo GetSystemHWID();

    // Terminate process immediately using Direct Syscalls and OpenProcess with PROCESS_TERMINATE
    bool TerminateTargetProcess(DWORD processId, const std::string& reason);

    // Enforce Hypervisor-Protected Code Integrity (HVCI) policy
    bool EnforceHVCIPolicy(bool strictBlock, std::string& outMessage);

    // Transmit JSON telemetry dossier to remote server / ban API via WinHttp
    bool DispatchBanTelemetry(const std::string& webhookUrl, const std::string& jsonDossier, const std::string& apiKey = "");

    // Process all critical alerts in real-time: auto-kill game + cheat and send ban telemetry with HWID payload
    EnforcementResult ProcessCriticalAlerts(DWORD gamePid, DWORD cheatPid, const std::string& reason, const EnforcementConfig& config, const std::string& jsonEvidencePath);
}
