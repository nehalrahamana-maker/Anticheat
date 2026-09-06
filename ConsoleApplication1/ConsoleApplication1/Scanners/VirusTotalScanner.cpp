#include "VirusTotalScanner.hpp"
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace VirusTotalScanner {

    // Default public/demo community endpoint or user-provided key
    static const char* k_DefaultPublicLookup = "https://www.virustotal.com/gui/file/";

    // ------------------------------------------------------------------ SHA-256 calculation
    std::string CalculateBufferSHA256(const BYTE* data, size_t size) {
        if (!data || size == 0) return "";

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        std::string hexHash = "";

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) {
            DWORD hashObjSize = 0, dataLen = 0;
            BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjSize, sizeof(DWORD), &dataLen, 0);

            std::vector<BYTE> hashObj(hashObjSize, 0);
            if (BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize, NULL, 0, 0) == 0) {
                BCryptHashData(hHash, (PBYTE)data, (ULONG)size, 0);

                BYTE hashResult[32] = { 0 };
                if (BCryptFinishHash(hHash, hashResult, sizeof(hashResult), 0) == 0) {
                    std::ostringstream ss;
                    for (int i = 0; i < 32; i++) {
                        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hashResult[i];
                    }
                    hexHash = ss.str();
                }
                BCryptDestroyHash(hHash);
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }
        return hexHash;
    }

    std::string CalculateFileSHA256(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return "";

        std::vector<BYTE> buffer(std::istreambuf_iterator<char>(file), {});
        if (buffer.empty()) return "";

        return CalculateBufferSHA256(buffer.data(), buffer.size());
    }

    std::string GetVirusTotalWebLink(const std::string& sha256) {
        if (sha256.empty()) return "";
        return std::string(k_DefaultPublicLookup) + sha256;
    }

    // ------------------------------------------------------------------ WinHTTP helper for VT API
    static std::string PerformWinHTTPRequest(
        const std::wstring& method,
        const std::wstring& path,
        const std::string& postData,
        const std::string& contentType,
        const std::string& apiKey)
    {
        std::string response = "";

        HINTERNET hSession = WinHttpOpen(
            L"WhiteTeamAntiCheat/4.0 (Windows NT 10.0; Win64; x64)",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);

        if (!hSession) return response;

        HINTERNET hConnect = WinHttpConnect(hSession, L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return response;
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            method.c_str(),
            path.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

        if (hRequest) {
            // Build headers
            std::wstring headers = L"Accept: application/json\r\n";
            if (!contentType.empty()) {
                headers += L"Content-Type: " + std::wstring(contentType.begin(), contentType.end()) + L"\r\n";
            }
            if (!apiKey.empty()) {
                headers += L"x-apikey: " + std::wstring(apiKey.begin(), apiKey.end()) + L"\r\n";
            }

            WinHttpAddRequestHeaders(hRequest, headers.c_str(), (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

            BOOL sent = WinHttpSendRequest(
                hRequest,
                WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                (LPVOID)(postData.empty() ? nullptr : postData.data()),
                (DWORD)postData.size(),
                (DWORD)postData.size(), 0);

            if (sent && WinHttpReceiveResponse(hRequest, nullptr)) {
                DWORD bytesAvailable = 0;
                while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
                    std::vector<char> tempBuf(bytesAvailable + 1, 0);
                    DWORD bytesRead = 0;
                    if (WinHttpReadData(hRequest, tempBuf.data(), bytesAvailable, &bytesRead)) {
                        response.append(tempBuf.data(), bytesRead);
                    }
                }
            }

            WinHttpCloseHandle(hRequest);
        }

        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    // ------------------------------------------------------------------ Query Hash API
    VTScanResult QueryFileHash(const std::string& sha256, const std::string& apiKey) {
        VTScanResult res;
        res.SHA256 = sha256;
        res.Permalink = GetVirusTotalWebLink(sha256);

        if (sha256.empty()) {
            res.ErrorMessage = "Empty SHA-256 hash provided.";
            return res;
        }

        if (apiKey.empty()) {
            // If no API key is provided, return ready-to-open permalink
            res.Success = true;
            res.ReputationVerdict = "ONLINE_LINK_READY";
            res.ThreatClassification = "Check via VirusTotal Web Portal";
            return res;
        }

        std::wstring path = L"/api/v3/files/" + std::wstring(sha256.begin(), sha256.end());
        std::string jsonResp = PerformWinHTTPRequest(L"GET", path, "", "", apiKey);

        if (jsonResp.empty()) {
            res.ErrorMessage = "No response from VirusTotal API v3.";
            return res;
        }

        // Basic parsing of attributes.last_analysis_stats
        if (jsonResp.find("\"malicious\":") != std::string::npos) {
            res.Success = true;

            auto ParseIntKey = [&](const std::string& key) -> int {
                size_t p = jsonResp.find("\"" + key + "\":");
                if (p != std::string::npos) {
                    size_t start = p + key.size() + 3;
                    return std::atoi(jsonResp.c_str() + start);
                }
                return 0;
            };

            res.MaliciousVotes = ParseIntKey("malicious");
            res.SuspiciousVotes = ParseIntKey("suspicious");
            res.HarmlessVotes = ParseIntKey("harmless");
            res.UndetectedVotes = ParseIntKey("undetected");
            res.TotalEngines = res.MaliciousVotes + res.SuspiciousVotes + res.HarmlessVotes + res.UndetectedVotes;

            if (res.MaliciousVotes > 0) {
                res.ReputationVerdict = "MALICIOUS";
                res.ThreatClassification = "Flagged by " + std::to_string(res.MaliciousVotes) + "/" + std::to_string(res.TotalEngines) + " Antivirus Engines";
            }
            else if (res.SuspiciousVotes > 0) {
                res.ReputationVerdict = "SUSPICIOUS";
                res.ThreatClassification = "Suspicious heuristics detected";
            }
            else {
                res.ReputationVerdict = "CLEAN";
                res.ThreatClassification = "Clean (0/" + std::to_string(res.TotalEngines) + " detections)";
            }
        }
        else {
            res.ReputationVerdict = "UNKNOWN";
            res.ThreatClassification = "Hash not yet seen by VirusTotal database";
        }

        return res;
    }

    // ------------------------------------------------------------------ Upload File to VT
    VTScanResult UploadFileToVT(const std::string& filePath, const std::string& apiKey) {
        VTScanResult res;
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            res.ErrorMessage = "Could not open local file: " + filePath;
            return res;
        }

        std::vector<BYTE> buffer(std::istreambuf_iterator<char>(file), {});
        file.close();

        std::string fname = filePath;
        size_t lastSlash = fname.find_last_of("\\/");
        if (lastSlash != std::string::npos) fname = fname.substr(lastSlash + 1);

        return UploadBufferToVT(buffer.data(), buffer.size(), fname, apiKey);
    }

    VTScanResult UploadBufferToVT(const BYTE* data, size_t size, const std::string& virtualFileName, const std::string& apiKey) {
        VTScanResult res;
        if (!data || size == 0) {
            res.ErrorMessage = "Empty payload buffer.";
            return res;
        }

        res.SHA256 = CalculateBufferSHA256(data, size);
        res.FileName = virtualFileName;
        res.Permalink = GetVirusTotalWebLink(res.SHA256);

        if (apiKey.empty()) {
            res.Success = true;
            res.ReputationVerdict = "ONLINE_LINK_READY";
            res.ThreatClassification = "Upload manually via: " + res.Permalink;
            return res;
        }

        // Build multipart/form-data payload
        std::string boundary = "----WhiteTeamBoundary992817462";
        std::ostringstream body;
        body << "--" << boundary << "\r\n";
        body << "Content-Disposition: form-data; name=\"file\"; filename=\"" << virtualFileName << "\"\r\n";
        body << "Content-Type: application/octet-stream\r\n\r\n";
        body.write(reinterpret_cast<const char*>(data), size);
        body << "\r\n--" << boundary << "--\r\n";

        std::string postPayload = body.str();
        std::string contentType = "multipart/form-data; boundary=" + boundary;

        std::string jsonResp = PerformWinHTTPRequest(L"POST", L"/api/v3/files", postPayload, contentType, apiKey);

        if (!jsonResp.empty() && jsonResp.find("\"data\":") != std::string::npos) {
            res.Success = true;
            res.ReputationVerdict = "SUBMITTED";
            res.ThreatClassification = "File successfully submitted to VirusTotal queue for analysis.";
        }
        else {
            res.ErrorMessage = "VirusTotal upload failed or invalid API response.";
        }

        return res;
    }

} // namespace VirusTotalScanner
