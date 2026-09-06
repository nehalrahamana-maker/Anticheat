#include <windows.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <vector>
#include <string>
#include <psapi.h>
#include <thread>

#include "SyscallEngine.hpp"
#include "PEParser.hpp"
#include "AntiTamper.hpp"
#include "StompScanner.hpp"
#include "HookScanner.hpp"
#include "SigScanner.hpp"
#include "DriverScanner.hpp"
#include "EmulatorScanner.hpp"
#include "VADScanner.hpp"
#include "ThreadInspector.hpp"
#include "OverlayAuditor.hpp"
#include "ArtifactScanner.hpp"
#include "RegistryArtifactScanner.hpp"
#include "NetworkAuditor.hpp"
#include "ProcessTreeAnalyzer.hpp"
#include "ScreenshotCapture.hpp"
#include "MemoryDumper.hpp"
#include "NTFSJournalScanner.hpp"
#include "TimelineScanner.hpp"
#include "EnforcementEngine.hpp"
#include "ReportGenerator.hpp"
#include "ImGuiDashboard.hpp"
#include "DLLProxyScanner.hpp"
#include "EncryptedStringScanner.hpp"
#include "SpoofedThreadScanner.hpp"
#include "ETWScanner.hpp"
#include "ProcessHollowingScanner.hpp"

// Check if running as administrator
static bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

// Enable SeDebugPrivilege
static bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    return ok && (GetLastError() == ERROR_SUCCESS);
}

static std::string GetCurrentTimestampString() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char buf[64] = { 0 };
    tm timeinfo;
    localtime_s(&timeinfo, &t);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &timeinfo);
    return std::string(buf);
}

void PrintBanner() {
    SetConsoleOutputCP(CP_UTF8);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (GetConsoleMode(hOut, &dwMode)) {
        SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    SetConsoleTitleA("NEHAL ANTI-CHEAT // CYBER-SOC FORENSIC COMMAND CENTER v3.5");

    std::cout << "\033[38;2;0;242;254m";
    std::cout << "███╗   ██╗███████╗██╗  ██╗ █████╗ ██╗         █████╗  ██████╗\n";
    std::cout << "\033[38;2;60;180;255m";
    std::cout << "████╗  ██║██╔════╝██║  ██║██╔══██╗██║        ██╔══██╗██╔════╝\n";
    std::cout << "\033[38;2;120;120;255m";
    std::cout << "██╔██╗ ██║█████╗  ███████║███████║██║        ███████║██║     \n";
    std::cout << "\033[38;2;180;60;255m";
    std::cout << "██║╚██╗██║██╔══╝  ██╔══██║██╔══██║██║        ██╔══██║██║     \n";
    std::cout << "\033[38;2;240;0;200m";
    std::cout << "██║ ╚████║███████╗██║  ██║██║  ██║███████╗   ██║  ██║╚██████╗\n";
    std::cout << "\033[38;2;255;0;128m";
    std::cout << "╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝  ╚═╝ ╚═════╝\n";
    std::cout << "\033[0m";
    std::cout << "\033[38;2;0;242;254m┌────────────────────────────────────────────────────────────────────────┐\033[0m\n";
    std::cout << "\033[38;2;0;242;254m│WHITE HAT !   \033[0m \033[38;2;0;242;254m│\033[0m\n";
    std::cout << "\033[38;2;0;242;254m│  \033[0m \033[38;2;0;242;254m│\033[0m\n";
    std::cout << "\033[38;2;0;242;254m└────────────────────────────────────────────────────────────────────────┘\033[0m\n\n";
}

int main(int argc, char* argv[]) {
    bool autoOpenBrowser = true;
    bool isBatchMode = false;
    bool isWatcherMode = false;
    bool isGuiMode = true; // DEFAULT TO IMGUI GUI!
    bool isCliMode = false;
    bool enforceHvci = false;
    DWORD targetPid = 0;
    std::string targetProcName = "";
    std::string disableSvcTarget = "";
    std::string dumpMemOut = "";
    ULONG_PTR dumpMemAddr = 0;
    SIZE_T dumpMemSize = 0;
    DWORD dumpMemPid = 0;
    std::string screenshotOut = "";

    EnforcementEngine::EnforcementConfig enforceConfig;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--gui") {
            isGuiMode = true;
        }
        else if (arg == "--cli") {
            isGuiMode = false;
            isCliMode = true;
        }
        else if (arg == "--no-browser") {
            autoOpenBrowser = false;
        }
        else if (arg == "--batch") {
            isBatchMode = true;
            isGuiMode = false;
            autoOpenBrowser = false;
        }
        else if (arg == "--watch") {
            isWatcherMode = true;
        }
        else if (arg == "--auto-kill") {
            enforceConfig.AutoKillEnabled = true;
        }
        else if (arg == "--enforce-hvci") {
            enforceHvci = true;
            enforceConfig.StrictHVCIRequired = true;
        }
        else if (arg == "--ban-webhook" && i + 1 < argc) {
            enforceConfig.BanWebhookUrl = argv[++i];
        }
        else if (arg == "--api-key" && i + 1 < argc) {
            enforceConfig.ServerApiKey = argv[++i];
        }
        else if (arg == "--pid" && i + 1 < argc) {
            targetPid = (DWORD)std::stoul(argv[++i]);
        }
        else if (arg == "--target" && i + 1 < argc) {
            targetProcName = argv[++i];
        }
        else if (arg == "--disable-service" && i + 1 < argc) {
            disableSvcTarget = argv[++i];
        }
        else if (arg == "--screenshot" && i + 1 < argc) {
            screenshotOut = argv[++i];
        }
        else if (arg == "--dump-mem" && i + 4 < argc) {
            dumpMemPid = (DWORD)std::stoul(argv[++i]);
            dumpMemAddr = (ULONG_PTR)std::stoull(argv[++i], nullptr, 16);
            dumpMemSize = (SIZE_T)std::stoull(argv[++i]);
            dumpMemOut = argv[++i];
        }
        else if (arg == "--help" || arg == "-h") {
            PrintBanner();
            std::cout << "Usage: AntiCheatScanner.exe [options]\n";
            std::cout << "Options:\n";
            std::cout << "  --gui                              Launch native DirectX 11 + Dear ImGui Cyber-SOC Desktop UI (Default)\n";
            std::cout << "  --cli                              Force CLI terminal scanner mode\n";
            std::cout << "  --target <Name>                    Target specific executable (defaults to HD-Player.exe if running)\n";
            std::cout << "  --pid <PID>                        Scan a specific process ID\n";
            std::cout << "  --watch                            Run in continuous live watcher mode (real-time protection)\n";
            std::cout << "  --auto-kill                        Instantly terminate cheat injector & game process upon threat\n";
            std::cout << "  --ban-webhook <URL>                Post JSON evidence dossier to ban server / webhook\n";
            std::cout << "  --enforce-hvci                     Block execution if Core Isolation / HVCI is disabled\n";
            std::cout << "  --screenshot <file.bmp>            Capture desktop/window forensic screenshot\n";
            std::cout << "  --dump-mem <PID> <HEX_ADDR> <SIZE> <OUTFILE> Dump raw suspicious memory region\n";
            std::cout << "  --disable-service <name>           Set Start=4 on malicious service (e.g. winVerb, RenaultDriver)\n";
            std::cout << "  --no-browser                       Do not automatically launch HTML proof panel\n";
            std::cout << "  --batch                            Headless batch mode for automated logging\n";
            std::cout << "  --help                             Display this help message\n";
            return 0;
        }
    }

    if (!isGuiMode) {
        PrintBanner();
    }
    else if (!isCliMode && !isBatchMode) {
        HWND hConsole = GetConsoleWindow();
        if (hConsole) {
            ShowWindow(hConsole, SW_HIDE);
        }
    }

    if (enforceHvci) {
        std::string hvciMsg;
        if (!EnforcementEngine::EnforceHVCIPolicy(true, hvciMsg)) {
            std::cout << "\033[91m[!] LAUNCH BLOCKED: " << hvciMsg << "\033[0m\n";
            return 1;
        }
        else {
            std::cout << "\033[92m[+] HVCI Policy Verified: " << hvciMsg << "\033[0m\n";
        }
    }

    // Direct Screenshot Utility
    if (!screenshotOut.empty()) {
        std::cout << "[*] Capturing desktop forensic screenshot to " << screenshotOut << "...\n";
        auto res = ScreenshotCapture::CaptureDesktopScreenshot(screenshotOut);
        if (res.Success) {
            std::cout << "[+] SUCCESS: Screenshot saved (" << res.Width << "x" << res.Height << ").\n";
        }
        else {
            std::cout << "[-] FAILED: " << res.ErrorMessage << "\n";
        }
        return 0;
    }

    // Direct Memory Dumper Utility
    if (!dumpMemOut.empty() && dumpMemPid > 0) {
        std::cout << "[*] Dumping 0x" << std::hex << dumpMemAddr << " (" << std::dec << dumpMemSize << " bytes) from PID " << dumpMemPid << "...\n";
        auto res = MemoryDumper::DumpMemoryRegion(dumpMemPid, dumpMemAddr, dumpMemSize, dumpMemOut);
        if (res.Success) {
            std::cout << "[+] SUCCESS: Dumped " << res.BytesDumped << " bytes to '" << res.SavedFilePath << "'. Ready for IDA Pro / Ghidra.\n";
        }
        else {
            std::cout << "[-] FAILED: " << res.ErrorMessage << "\n";
        }
        return 0;
    }

    // Check Administrator Rights
    if (IsRunningAsAdmin()) {
        EnableDebugPrivilege();
    }

    // Remediation Option: Disable Service
    if (!disableSvcTarget.empty()) {
        std::cout << "[*] Attempting to disable service: " << disableSvcTarget << "...\n";
        if (DriverScanner::DisableService(disableSvcTarget)) {
            std::cout << "[+] SUCCESS: Service '" << disableSvcTarget << "' disabled (Start=4). Reboot required.\n";
        }
        else {
            std::cout << "[-] FAILED: Could not modify registry for service '" << disableSvcTarget << "'. Are you admin?\n";
        }
        return 0;
    }

    // Initialize Direct Syscall Engine
    SyscallEngine::Initialize();

    // Query Real-Time Hardware Profile
    auto liveHWID = EnforcementEngine::GetSystemHWID();
    if (!isGuiMode) {
        std::cout << "\033[38;2;0;242;254m[+] Hardware Fingerprint Armed:\033[0m \033[1;92m" << liveHWID.CompositeHWID << "\033[0m\n";
        std::cout << "\033[38;2;0;242;254m[+] Hardware Profile:\033[0m CPU: " << liveHWID.CPUBrand << " | GPU: " << liveHWID.GPUDescription << "\n";
        std::cout << "\033[38;2;0;242;254m[+] Hardware Serials:\033[0m MB-UUID: " << liveHWID.MotherboardUUID << " | Disk0: " << liveHWID.DiskSerial << "\n\n";
    }

    // Auto-discover HD-Player.exe or Android emulators if no target specified
    if (targetPid == 0 && targetProcName.empty()) {
        auto emulators = EmulatorScanner::FindRunningEmulators();
        if (!emulators.empty()) {
            targetPid = emulators[0].ProcessId;
            targetProcName = emulators[0].ProcessName;
        }
    }
    else if (!targetProcName.empty() && targetPid == 0) {
        auto emulators = EmulatorScanner::FindRunningEmulators();
        for (const auto& emu : emulators) {
            if (_stricmp(emu.ProcessName.c_str(), targetProcName.c_str()) == 0) {
                targetPid = emu.ProcessId;
                break;
            }
        }
    }

    // Lambda to perform a complete deep scan iteration
    auto PerformScanIteration = [&](bool isLiveLoop, DWORD overridePid = 0, const std::string& overrideName = "", ImGuiDashboard::ProgressCallback onProgress = nullptr) -> ReportGenerator::ScanReportData {
        DWORD curTargetPid = (overridePid > 0) ? overridePid : targetPid;
        std::string curTargetName = (!overrideName.empty()) ? overrideName : (targetProcName.empty() ? "HD-Player.exe" : targetProcName);

        ReportGenerator::ScanReportData report;
        report.ScanTimestamp = GetCurrentTimestampString();
        report.TotalProcessesScanned = 0;
        report.TotalModulesScanned = 0;
        report.IsWatcherMode = isWatcherMode;
        report.TamperStatus = AntiTamper::AuditSelfIntegrity();
        report.TargetProcessName = curTargetName;

        auto startTime = std::chrono::high_resolution_clock::now();

        auto ReportProgress = [&](float p, const std::string& title, const std::string& subtext, const std::string& liveItem) {
            if (onProgress) onProgress(p, title, subtext, liveItem);
        };

        // 1. Check System HVCI / VBS Status
        ReportProgress(0.055f, "[01/18] Auditing Kernel Integrity & Core Isolation (HVCI)...", "Checking Secure Boot, VBS policy, and hypervisor integrity...", "[01/18] Auditing UEFI Secure Boot & DeviceGuard HVCI Policy");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [01/18]\033[0m Auditing Kernel Integrity & Core Isolation (HVCI)...\n";
        report.HVCIStatus = DriverScanner::CheckHVCIStatus();

        // 2. Scan Kernel Driver Persistence & Loaded/Mapped Drivers
        ReportProgress(0.110f, "[02/18] Scanning System Drivers, Loaded Modules & Mapped Drivers...", "Auditing loaded Ring-0 drivers, unsigned binaries, BYOVD & kdmapper...", "[02/18] Enumerating Active Ring-0 Kernel Drivers & BYOVD Exploit DB");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [02/18]\033[0m Scanning System Drivers, Loaded Modules & Mapped Drivers (BYOVD / kdmapper)...\n";
        report.DriverDetections = DriverScanner::ScanDriverServices();
        report.LoadedDriverDetections = DriverScanner::ScanLoadedKernelDrivers();
        report.MappedDriverDetections = DriverScanner::ScanMappedDriverForensics();

        // 3. Scan File System & Prefetch Execution Artifacts
        ReportProgress(0.165f, "[03/18] Auditing File System & Prefetch Execution History...", "Parsing Windows prefetch hashes & Temp/LocalAppData payloads...", "[03/18] Parsing C:\\Windows\\Prefetch & Temporary Staging Directories");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [03/18]\033[0m Auditing File System Evidence & Windows Prefetch Execution History...\n";
        report.FileArtifactDetections = ArtifactScanner::ScanFileSystemArtifacts();

        // 4. Scan Registry Traces (BAM, MuiCache, UserAssist)
        ReportProgress(0.220f, "[04/18] Auditing Execution Ledger & Registry Artifacts (BAM/DAM)...", "Decoding 64-bit FILETIME binary execution ledgers...", "[04/18] Walking HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [04/18]\033[0m Auditing Execution Ledger & Registry Artifacts (BAM / MuiCache / AppCompatFlags)...\n";
        report.RegArtifactDetections = RegistryArtifactScanner::ScanRegistryArtifacts();

        // 5. Audit Active Network Connections (C2 Hunter)
        ReportProgress(0.275f, "[05/18] Auditing Outbound Network Sockets & Remote Endpoints...", "Inspecting active TCP/UDP endpoints via extended IPHLPAPI...", "[05/18] Querying Extended TCP/UDP Connection Table via IpHlpApi");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [05/18]\033[0m Auditing Active Network Sockets & Remote Endpoints...\n";
        report.NetworkConnections = NetworkAuditor::AuditNetworkConnections(curTargetPid);

        // 6. Analyze Process Tree & Loader Hierarchies
        ReportProgress(0.330f, "[06/18] Analyzing Process Hierarchy & Parent-Child Trees...", "Detecting orphaned loader relationships and process spoofing...", "[06/18] Auditing Process Hierarchy, PPID Spoofing & Staged Loaders");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [06/18]\033[0m Analyzing Process Hierarchy & Loader Relationships...\n";
        report.ProcessTreeDetections = ProcessTreeAnalyzer::AnalyzeProcessTrees();

        // 7. Scan Rogue clb.dll in System Directories
        ReportProgress(0.385f, "[07/18] Inspecting API Prologues & Syscall Hook Integrity...", "Inspecting System32/SysWOW64 for rogue DLL hooks & registry shims...", "[07/18] Inspecting NTDLL Export Prologues & clb.dll Registry Sideloads");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [07/18]\033[0m Inspecting API Prologues & Syscall Hook Integrity...\n";
        report.ClbDllDetections = HookScanner::ScanSystemClbDll();

        // 8. Scan Process Signatures & Bad Digest
        ReportProgress(0.440f, "[08/18] Validating Binary Authenticode & Digital Signatures...", "Verifying WinVerifyTrust signatures & digest hashes...", "[08/18] Validating Binary Authenticode Signatures via WinVerifyTrust");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [08/18]\033[0m Validating Binary Authenticode & Digital Signatures...\n";
        if (curTargetPid > 0) {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, curTargetPid);
            if (h) {
                WCHAR szPath[MAX_PATH] = { 0 };
                DWORD dwSize = MAX_PATH;
                if (QueryFullProcessImageNameW(h, 0, szPath, &dwSize)) {
                    auto det = SigScanner::ScanBinarySignature(szPath);
                    if (det.Severity == "CRITICAL" || det.Severity == "HIGH") {
                        report.SigDetections.push_back(det);
                    }
                }
                CloseHandle(h);
            }
        }
        else {
            report.SigDetections = SigScanner::ScanRunningProcessesSignatures();
        }

        // 9. Memory Stomping & API Hooks
        ReportProgress(0.495f, "[09/18] Verifying Dynamic Code & Module Memory Integrity...", "Performing SIMD byte diff of in-memory code vs signed disk PE...", "[09/18] SIMD Byte-Diffing In-Memory Code Sections vs Signed Disk PEs");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [09/18]\033[0m Verifying Dynamic Code & Module Memory Integrity...\n";
        if (curTargetPid > 0) {
            report.StompDetections = StompScanner::ScanProcess(curTargetPid, curTargetName);
            report.HookDetections = HookScanner::ScanApiHooks(curTargetPid, curTargetName);
            report.TotalProcessesScanned = 1;
        }
        else {
            DWORD pids[2048];
            DWORD cbNeeded;
            if (EnumProcesses(pids, sizeof(pids), &cbNeeded)) {
                report.TotalProcessesScanned = cbNeeded / sizeof(DWORD);
            }
            report.StompDetections = StompScanner::ScanAllProcesses();
            report.HookDetections = HookScanner::ScanAllProcessHooks();
        }

        // 10. VAD Unbacked Executable Memory & PEB Unlinking Hunter
        ReportProgress(0.550f, "[10/18] Walking Kernel VAD Tree & Page Allocation Tables...", "Scanning unbacked PAGE_EXECUTE_READWRITE and floating code pages...", "[10/18] Walking Virtual Address Descriptor (VAD) Tree & RX/RWX Pages");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [10/18]\033[0m Walking Kernel VAD Tree (Unbacked Executable Memory Pages)...\n";
        if (curTargetPid > 0) {
            report.VADDetections = VADScanner::ScanProcessVAD(curTargetPid, curTargetName);
        }

        // 11. Thread Inspector & Overlay Auditor
        ReportProgress(0.605f, "[11/18] Auditing Thread Context Integrity & APC Queues...", "Inspecting CPU hardware breakpoint registers (Dr0-Dr7) & APC traps...", "[11/18] Auditing CPU Hardware Breakpoint Registers (Dr0-Dr7) & APC Traps");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [11/18]\033[0m Auditing Thread Context Integrity (Dr0-Dr7), Handles & Overlays...\n";
        if (curTargetPid > 0) {
            report.ThreadDetections = ThreadInspector::InspectProcessThreads(curTargetPid, curTargetName);
            report.EmulatorDetections = EmulatorScanner::ScanEmulatorIntegrity(curTargetPid, curTargetName);
        }
        report.OverlayDetections = OverlayAuditor::ScanOverlayWindows(curTargetPid);

        // 12. NTFS Alternate Data Streams (Zone.Identifier MOTW & Hidden Payloads)
        ReportProgress(0.660f, "[12/18] Auditing Alternate Data Streams (Zone.Identifier)...", "Scanning Mark-of-the-Web zone identifiers & hidden NTFS streams...", "[12/18] Scanning NTFS Alternate Data Streams (Zone.Identifier MOTW)");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [12/18]\033[0m Auditing Alternate Data Streams (Zone.Identifier)...\n";
        report.NTFSDetections = NTFSJournalScanner::ScanNTFSArtifacts();

        // 13. Windows Timeline & PCA Execution History
        ReportProgress(0.715f, "[13/18] Parsing Application History & Timeline Cache...", "Scanning ActivitiesCache.db & AppCompatFlags execution records...", "[13/18] Parsing Windows ActivitiesCache.db & PCA Compatibility Cache");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [13/18]\033[0m Parsing Application History (ActivitiesCache.db) & PCA Execution Logs...\n";
        report.TimelineDetections = TimelineScanner::ScanTimelineActivities();

        // 14. DLL Proxy / Search-Order Hijack Detection
        ReportProgress(0.770f, "[14/18] Scanning for DLL Proxy & Search-Order Hijacks...", "Comparing loaded module paths against System32 canonical paths & checking forwarded exports...", "[14/18] DLL Proxy Scanner — Real vs Fake Path & Export-Forward Shim");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [14/18]\033[0m Scanning for DLL Proxy / Search-Order Hijacks (real vs fake path)...\n";
        if (curTargetPid > 0) {
            report.DLLProxyDetections = DLLProxyScanner::ScanProcessDLLProxy(curTargetPid, curTargetName);
        } else {
            report.DLLProxyDetections = DLLProxyScanner::ScanAllProcessesDLLProxy();
        }

        // 15. Encrypted / Obfuscated String Detection In Memory
        ReportProgress(0.825f, "[15/18] Scanning Process Memory for Encrypted Cheat Strings...", "Brute-forcing XOR keys, detecting RC4 S-boxes, Base64 payloads & ROT encoded strings...", "[15/18] Encrypted String Scanner — XOR / RC4 / Base64 / ROT");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [15/18]\033[0m Scanning for Encrypted / Obfuscated Cheat Strings in Memory...\n";
        if (curTargetPid > 0) {
            report.EncryptedStringDetections = EncryptedStringScanner::ScanProcessEncryptedStrings(curTargetPid, curTargetName);
        } else {
            report.EncryptedStringDetections = EncryptedStringScanner::ScanAllProcessesEncryptedStrings();
        }

        // 16. Spoofed Call-Stack / Thread Context Hijack Detection
        ReportProgress(0.880f, "[16/18] Auditing Thread Call-Stacks for Spoof / Pivot Attacks...", "Walking return-address chains, checking RSP vs TEB stack bounds, detecting fake frame chains...", "[16/18] Spoofed Thread Scanner — Stack Pivot / Return-Address Spoof / Context Hijack");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [16/18]\033[0m Auditing Thread Call-Stacks for Spoof & Pivot Attacks...\n";
        if (curTargetPid > 0) {
            report.SpoofedThreadDetections = SpoofedThreadScanner::ScanProcessSpoofedThreads(curTargetPid, curTargetName);
        } else {
            report.SpoofedThreadDetections = SpoofedThreadScanner::ScanAllProcessesSpoofedThreads();
        }

        // 17. ETW & Event Log Tampering Detection
        ReportProgress(0.935f, "[17/18] Auditing ETW & EventLog Telemetry Suppression...", "Checking EtwEventWrite/Full hooks and verifying EventLog service thread suspend counts...", "[17/18] ETW & EventLog Scanner — EtwpEventWriteFull Patch & Thread Suspend Audit");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [17/18]\033[0m Auditing ETW & EventLog Telemetry Suppression...\n";
        if (curTargetPid > 0) {
            report.ETWDetections = ETWScanner::ScanProcessETWIntegrity(curTargetPid, curTargetName);
        } else {
            report.ETWDetections = ETWScanner::ScanAllProcessesETW();
        }

        // 18. Process Hollowing, Doppelganging & Ghosting Hunter
        ReportProgress(0.990f, "[18/18] Scanning for Process Hollowing & Doppelganging...", "Verifying PEB ImageBase against disk image, checking AddressOfEntryPoint & unbacked main PE...", "[18/18] Process Hollowing Scanner — PE Header Diff & Unbacked Image Base");
        if (!isLiveLoop && !isGuiMode) std::cout << "\033[38;2;0;242;254m[*] [18/18]\033[0m Scanning for Process Hollowing & Doppelganging...\n";
        if (curTargetPid > 0) {
            report.HollowingDetections = ProcessHollowingScanner::ScanProcessHollowing(curTargetPid, curTargetName);
        } else {
            report.HollowingDetections = ProcessHollowingScanner::ScanAllProcessesHollowing();
        }

        // Extract Hardware Ban Fingerprint (HWID)
        report.SystemHWID = EnforcementEngine::GetSystemHWID();

        auto endTime = std::chrono::high_resolution_clock::now();
        double elapsedMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();

        if (!isLiveLoop && !isGuiMode) {
            std::cout << "\033[92m[+] Complete 18-Engine Sweep Finished in " << std::fixed << std::setprecision(2) << (elapsedMs / 1000.0) << " seconds.\033[0m\n\n";
        }

        return report;
    };

    if (isGuiMode) {
        std::cout << "\033[92m[+] Launching DirectX 11 + Dear ImGui Cyber-SOC Desktop Interface...\033[0m\n";
        auto scanCallback = [&](DWORD pid, const std::string& name, ImGuiDashboard::ProgressCallback onProgress) -> ReportGenerator::ScanReportData {
            return PerformScanIteration(false, pid, name, onProgress);
        };
        return ImGuiDashboard::Run(GetModuleHandle(NULL), SW_SHOWDEFAULT, scanCallback, targetPid, targetProcName);
    }

    if (isWatcherMode) {
        std::cout << "\033[93m[*] LIVE CYBER-SOC WATCHER MODE ENGAGED. Monitoring " << (targetProcName.empty() ? "all processes" : targetProcName) 
                  << " in real-time... (Press Ctrl+C to stop)\033[0m\n\n";

        bool firstRun = true;
        while (true) {
            auto report = PerformScanIteration(true);

            size_t totalAlerts = report.StompDetections.size() + report.HookDetections.size() +
                report.SigDetections.size() + report.DriverDetections.size() +
                report.EmulatorDetections.size() + report.VADDetections.size() +
                report.ThreadDetections.size() + report.OverlayDetections.size() +
                report.FileArtifactDetections.size() + report.RegArtifactDetections.size() +
                report.NetworkConnections.size() + report.ProcessTreeDetections.size() +
                report.NTFSDetections.size() + report.TimelineDetections.size() +
                report.DLLProxyDetections.size() + report.EncryptedStringDetections.size() +
                report.SpoofedThreadDetections.size() +
                report.ETWDetections.size() + report.HollowingDetections.size();

            ReportGenerator::GenerateHTMLProofPanel(report, "DetectionPanel.html", firstRun && autoOpenBrowser);
            ReportGenerator::GenerateJSONReport(report, "ScanEvidence.json");
            firstRun = false;

            // Trigger Real-Time Enforcement (Auto-Kill & Ban Telemetry) if threats exist
            if (totalAlerts > 0 && (enforceConfig.AutoKillEnabled || !enforceConfig.BanWebhookUrl.empty())) {
                DWORD suspectCheatPid = 0;
                std::string killReason = "Critical Threat Detected";

                if (!report.EmulatorDetections.empty()) {
                    suspectCheatPid = report.EmulatorDetections.front().ProcessId;
                    killReason = "Unauthorized Handle Bridge to Game";
                }
                else if (!report.StompDetections.empty()) {
                    suspectCheatPid = report.StompDetections.front().ProcessId;
                    killReason = "Dynamic Code Anomaly in " + report.StompDetections.front().ModuleName;
                }
                else if (!report.VADDetections.empty()) {
                    suspectCheatPid = report.VADDetections.front().ProcessId;
                    killReason = "Unbacked Executable Memory Page";
                }
                else if (!report.HollowingDetections.empty()) {
                    suspectCheatPid = report.HollowingDetections.front().ProcessId;
                    killReason = "Process Hollowing / PE Tampering Detected";
                }

                EnforcementEngine::ProcessCriticalAlerts(targetPid, suspectCheatPid, killReason, enforceConfig, "ScanEvidence.json");
            }

            std::cout << "\r[" << report.ScanTimestamp << "] SOC Status: "
                      << (totalAlerts > 0 ? "\033[91m🚨 " + std::to_string(totalAlerts) + " THREATS ISOLATED!\033[0m" : "\033[92m🛡️ SECURE (0 Threats)\033[0m") 
                      << "  " << std::flush;

            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        }
    }
    else {
        auto report = PerformScanIteration(false);

        size_t totalAlerts = report.StompDetections.size() + report.HookDetections.size() +
            report.SigDetections.size() + report.DriverDetections.size() +
            report.LoadedDriverDetections.size() + report.MappedDriverDetections.size() +
            report.EmulatorDetections.size() + report.VADDetections.size() +
            report.ThreadDetections.size() + report.OverlayDetections.size() +
            report.FileArtifactDetections.size() + report.RegArtifactDetections.size() +
            report.NetworkConnections.size() + report.ProcessTreeDetections.size() +
            report.NTFSDetections.size() + report.TimelineDetections.size() +
            report.DLLProxyDetections.size() + report.EncryptedStringDetections.size() +
            report.SpoofedThreadDetections.size() +
            report.ETWDetections.size() + report.HollowingDetections.size();

        // Trigger Real-Time Enforcement (Auto-Kill & Ban Telemetry) if threats exist
        if (totalAlerts > 0 && (enforceConfig.AutoKillEnabled || !enforceConfig.BanWebhookUrl.empty())) {
            DWORD suspectCheatPid = 0;
            std::string killReason = "Critical Threat Detected";

            if (!report.EmulatorDetections.empty()) {
                suspectCheatPid = report.EmulatorDetections.front().ProcessId;
                killReason = "Unauthorized Handle Bridge to Game";
            }
            else if (!report.StompDetections.empty()) {
                suspectCheatPid = report.StompDetections.front().ProcessId;
                killReason = "Dynamic Code Anomaly in " + report.StompDetections.front().ModuleName;
            }
            else if (!report.VADDetections.empty()) {
                suspectCheatPid = report.VADDetections.front().ProcessId;
                killReason = "Unbacked Executable Memory Page";
            }
            else if (!report.HollowingDetections.empty()) {
                suspectCheatPid = report.HollowingDetections.front().ProcessId;
                killReason = "Process Hollowing / PE Tampering Detected";
            }
            else if (!report.MappedDriverDetections.empty()) {
                killReason = "Manual Mapped Driver / BYOVD Exploit Driver Detected";
            }

            EnforcementEngine::ProcessCriticalAlerts(targetPid, suspectCheatPid, killReason, enforceConfig, "ScanEvidence.json");
        }

        std::cout << "\033[38;2;0;242;254m┌────────────────────────────────────────────────────────────────────────┐\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m \033[1;38;2;255;255;255m         NEHAL ANTI-CHEAT // FORENSIC TRIAGE SUMMARY (v3.5)             \033[0m \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m├────────────────────────────────────────────────────────────────────────┤\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Total Processes Audited:             \033[38;2;0;242;254m" << std::setw(6) << report.TotalProcessesScanned << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Dynamic Code & Module Integrity:     \033[38;2;255;30;86m" << std::setw(6) << report.StompDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Cross-Process Handle Bridges:        \033[38;2;255;30;86m" << std::setw(6) << report.EmulatorDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Unbacked Executable Memory (VAD):    \033[38;2;255;30;86m" << std::setw(6) << report.VADDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Thread APC & Context Integrity (Dr#):\033[38;2;255;30;86m" << std::setw(6) << report.ThreadDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Transparent Viewport & Overlays:     \033[38;2;255;119;0m" << std::setw(6) << report.OverlayDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Prefetch & File System Evidence:     \033[38;2;255;30;86m" << std::setw(6) << report.FileArtifactDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Execution Ledger & BAM Artifacts:    \033[38;2;255;30;86m" << std::setw(6) << report.RegArtifactDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Alternate Data Streams (Zone.Id):    \033[38;2;255;30;86m" << std::setw(6) << report.NTFSDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Application History & Timeline:      \033[38;2;255;119;0m" << std::setw(6) << report.TimelineDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Outbound Network Sockets:            \033[38;2;255;30;86m" << std::setw(6) << report.NetworkConnections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Process Hierarchy & Loaders:         \033[38;2;255;30;86m" << std::setw(6) << report.ProcessTreeDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  API Prologue & Syscall Integrity:    \033[38;2;255;30;86m" << std::setw(6) << (report.HookDetections.size() + report.ClbDllDetections.size()) << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Binary Authenticode Signatures:      \033[38;2;255;30;86m" << std::setw(6) << report.SigDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  System Drivers & Boot Persistence:   \033[38;2;255;30;86m" << std::setw(6) << report.DriverDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Mapped Drivers & Unsigned Modules:   \033[38;2;255;30;86m" << std::setw(6) << (report.LoadedDriverDetections.size() + report.MappedDriverDetections.size()) << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  DLL Proxy / Search-Order Hijacks:    \033[38;2;255;30;86m" << std::setw(6) << report.DLLProxyDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Encrypted / Obfuscated Strings:      \033[38;2;255;30;86m" << std::setw(6) << report.EncryptedStringDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Spoofed Call-Stack / Thread Hijacks: \033[38;2;255;30;86m" << std::setw(6) << report.SpoofedThreadDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  ETW / EventLog Telemetry Suppression:\033[38;2;255;30;86m" << std::setw(6) << report.ETWDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Process Hollowing & Doppelganging:   \033[38;2;255;30;86m" << std::setw(6) << report.HollowingDetections.size() << "\033[0m                                 \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  Hardware Ban Fingerprint (HWID):     \033[38;2;0;242;254m" << (report.SystemHWID.CompositeHWID.empty() ? "HWID-READY" : report.SystemHWID.CompositeHWID) << "\033[0m          \033[38;2;0;242;254m│\033[0m\n";
        std::cout << "\033[38;2;0;242;254m├────────────────────────────────────────────────────────────────────────┤\033[0m\n";
        std::cout << "\033[38;2;0;242;254m│\033[0m  TOTAL ANOMALIES DETECTED:           " << (totalAlerts > 0 ? "\033[1;38;2;255;30;86m" + std::to_string(totalAlerts) + " [THREATS ISOLATED]\033[0m" : "\033[1;38;2;0;245;160m0 [CLEAN / VERIFIED]\033[0m") << "\n";
        std::cout << "\033[38;2;0;242;254m└────────────────────────────────────────────────────────────────────────┘\033[0m\n\n";

        std::cout << "\033[38;2;0;242;254m[*] Generating Cyber SOC Forensic Proof Panel (DetectionPanel.html)...\033[0m\n";
        ReportGenerator::GenerateHTMLProofPanel(report, "DetectionPanel.html", autoOpenBrowser);

        std::cout << "\033[38;2;0;242;254m[*] Exporting JSON Forensic Dossier (ScanEvidence.json)...\033[0m\n";
        ReportGenerator::GenerateJSONReport(report, "ScanEvidence.json");

        if (totalAlerts > 0) {
            MessageBeep(MB_ICONEXCLAMATION);
        }
        else {
            MessageBeep(MB_OK);
        }

        std::cout << "\n\033[92m[+] Ready! Check your browser for the Cyberpunk SOC Proof Panel.\033[0m\n";
        if (autoOpenBrowser && !isBatchMode) {
            std::cout << "Press Enter to exit.\n";
            std::cin.get();
        }
    }

    SyscallEngine::Cleanup();
    return 0;
}
