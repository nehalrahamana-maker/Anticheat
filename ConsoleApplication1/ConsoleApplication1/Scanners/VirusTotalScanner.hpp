#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace VirusTotalScanner {

    struct VTScanResult {
        bool Success = false;
        std::string SHA256;
        std::string FileName;
        int MaliciousVotes = 0;
        int SuspiciousVotes = 0;
        int HarmlessVotes = 0;
        int UndetectedVotes = 0;
        int TotalEngines = 0;
        std::string ReputationVerdict;  // "CLEAN", "MALICIOUS", "SUSPICIOUS", "UNKNOWN"
        std::string ThreatClassification; // e.g. "HackTool.Win64.CheatEngine"
        std::string Permalink;          // Direct VirusTotal GUI URL
        std::string ErrorMessage;
    };

    // Calculate SHA-256 hash of a file on disk
    std::string CalculateFileSHA256(const std::string& filePath);

    // Calculate SHA-256 hash of a memory buffer
    std::string CalculateBufferSHA256(const BYTE* data, size_t size);

    // Query VirusTotal v3 API for a file SHA-256 hash (GET https://www.virustotal.com/api/v3/files/{hash})
    VTScanResult QueryFileHash(const std::string& sha256, const std::string& apiKey = "");

    // Upload a suspect file or memory dump to VirusTotal v3 API (POST https://www.virustotal.com/api/v3/files)
    VTScanResult UploadFileToVT(const std::string& filePath, const std::string& apiKey = "");

    // Upload an in-memory buffer (e.g. dumped unbacked shellcode) to VirusTotal
    VTScanResult UploadBufferToVT(const BYTE* data, size_t size, const std::string& virtualFileName, const std::string& apiKey = "");

    // Generate web GUI lookup link for any SHA-256
    std::string GetVirusTotalWebLink(const std::string& sha256);

} // namespace VirusTotalScanner
