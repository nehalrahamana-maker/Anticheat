#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <string>
#include <vector>
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
#include "NTFSJournalScanner.hpp"
#include "TimelineScanner.hpp"
#include "AntiTamper.hpp"
#include "EnforcementEngine.hpp"
// Advanced scanners
#include "DLLProxyScanner.hpp"
#include "EncryptedStringScanner.hpp"
#include "SpoofedThreadScanner.hpp"
#include "ETWScanner.hpp"
#include "ProcessHollowingScanner.hpp"

namespace ReportGenerator {

    struct GenericDetection {
        std::string DetectionName;
        std::string Severity;
        std::string Description;
        std::string MatchedPattern;
        float Confidence = 1.0f;
    };

    struct ScanReportData {
        DWORD TotalProcessesScanned = 0;
        DWORD TotalModulesScanned = 0;
        std::vector<StompScanner::StompDetection> StompDetections;
        std::vector<HookScanner::HookDetection> HookDetections;
        std::vector<HookScanner::ClbDllDetection> ClbDllDetections;
        std::vector<SigScanner::SignatureDetection> SigDetections;
        std::vector<DriverScanner::DriverServiceDetection> DriverDetections;
        std::vector<DriverScanner::LoadedDriverDetection> LoadedDriverDetections;
        std::vector<DriverScanner::MappedDriverDetection> MappedDriverDetections;
        std::vector<EmulatorScanner::EmulatorDetection> EmulatorDetections;
        std::vector<VADScanner::VADDetection> VADDetections;
        std::vector<ThreadInspector::ThreadDetection> ThreadDetections;
        std::vector<OverlayAuditor::OverlayDetection> OverlayDetections;
        std::vector<ArtifactScanner::FileArtifactDetection> FileArtifactDetections;
        std::vector<RegistryArtifactScanner::RegArtifactDetection> RegArtifactDetections;
        std::vector<NetworkAuditor::NetworkConnection> NetworkConnections;
        std::vector<ProcessTreeAnalyzer::ProcessTreeDetection> ProcessTreeDetections;
        std::vector<NTFSJournalScanner::NTFSArtifactDetection> NTFSDetections;
        std::vector<TimelineScanner::TimelineDetection> TimelineDetections;
        DriverScanner::HVCISecurityStatus HVCIStatus;
        AntiTamper::AntiTamperStatus TamperStatus;
        EnforcementEngine::SystemHWIDInfo SystemHWID;
        std::string ScanTimestamp;
        std::string TargetProcessName = "HD-Player.exe";
        bool IsWatcherMode = false;

        // Advanced scanner results
        std::vector<DLLProxyScanner::DLLProxyDetection>               DLLProxyDetections;
        std::vector<EncryptedStringScanner::EncryptedStringDetection> EncryptedStringDetections;
        std::vector<SpoofedThreadScanner::SpoofedThreadDetection>     SpoofedThreadDetections;
        std::vector<ETWScanner::ETWDetection>                         ETWDetections;
        std::vector<ProcessHollowingScanner::ProcessHollowingDetection> HollowingDetections;

        // Forensic & Custom Scanners
        std::vector<GenericDetection> CheatStringDetections;
        std::vector<GenericDetection> PSDetections;
        std::vector<GenericDetection> PrefetchDetections;
        std::vector<GenericDetection> DnsDetections;
        std::vector<GenericDetection> ShimcacheDetections;
        std::vector<GenericDetection> AmcacheDetections;
        std::vector<GenericDetection> YaraDetections;
    };

    // Generate self-contained interactive HTML proof panel and launch it in default browser
    bool GenerateHTMLProofPanel(const ScanReportData& report, const std::string& outputPath = "DetectionPanel.html", bool autoOpen = true);

    // Generate JSON file for automated ingestion / backend logging
    bool GenerateJSONReport(const ScanReportData& report, const std::string& outputPath = "ScanEvidence.json");
}
