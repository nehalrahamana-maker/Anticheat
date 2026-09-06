#include "NTFSJournalScanner.hpp"
#include <shlobj.h>
#include <shlwapi.h>
#include <iostream>
#include <algorithm>
#include <vector>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

namespace NTFSJournalScanner {

    static std::string ToLower(const std::string& str) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower;
    }

    static void CheckFileStreams(const std::wstring& filePathW, const std::string& filePathA, std::vector<NTFSArtifactDetection>& detections) {
        WIN32_FIND_STREAM_DATA fsd;
        HANDLE hFindStream = FindFirstStreamW(filePathW.c_str(), FindStreamInfoStandard, &fsd, 0);
        if (hFindStream == INVALID_HANDLE_VALUE) return;

        do {
            char streamNameBuf[MAX_PATH] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, fsd.cStreamName, -1, streamNameBuf, MAX_PATH, NULL, NULL);
            std::string streamName = streamNameBuf;
            std::string streamLower = ToLower(streamName);

            // Ignore standard default stream (::$DATA)
            if (streamLower != "::$data" && !streamName.empty()) {
                // Heuristic 1: Any alternate data stream containing executable payloads or hidden data
                if (streamLower.find(".exe") != std::string::npos || streamLower.find(".dll") != std::string::npos ||
                    streamLower.find(".sys") != std::string::npos || streamLower.find(":payload") != std::string::npos ||
                    streamLower.find(":code") != std::string::npos || streamLower.find(":inject") != std::string::npos ||
                    (streamLower != ":zone.identifier:$data" && fsd.StreamSize.QuadPart > 1024)) {
                    
                    NTFSArtifactDetection d;
                    d.TargetPath = filePathA;
                    d.StreamName = streamName;
                    d.ArtifactType = "HIDDEN_PAYLOAD_ALTERNATE_STREAM";
                    d.Severity = "CRITICAL";
                    d.Description = "Hidden Alternate Data Stream '" + streamName + "' (" + std::to_string(fsd.StreamSize.QuadPart) + 
                                    " bytes) attached to file '" + filePathA + "'. Common evasion technique used by stealth injectors.";
                    detections.push_back(d);
                }
                // Heuristic 2: Mark of the Web (Zone.Identifier) on binaries in temporary/staging paths
                else if (streamLower.find(":zone.identifier") != std::string::npos) {
                    std::string fileLower = ToLower(filePathA);
                    if (fileLower.find("\\temp\\") != std::string::npos || fileLower.find("\\appdata\\") != std::string::npos ||
                        fileLower.find("\\users\\public\\") != std::string::npos) {
                        
                        NTFSArtifactDetection d;
                        d.TargetPath = filePathA;
                        d.StreamName = streamName;
                        d.ArtifactType = "UNTRUSTED_WEB_DOWNLOAD_MOTW";
                        d.Severity = "HIGH";
                        d.Description = "Mark of the Web (Zone.Identifier) confirms executable '" + filePathA + "' was downloaded from an external untrusted web source.";
                        detections.push_back(d);
                    }
                }
            }
        } while (FindNextStreamW(hFindStream, &fsd));

        FindClose(hFindStream);
    }

    static void ScanDirectoryForStreams(const std::wstring& dirPath, int maxDepth, std::vector<NTFSArtifactDetection>& detections) {
        if (maxDepth <= 0) return;

        std::wstring searchPattern = dirPath + L"\\*";
        WIN32_FIND_DATAW ffd;
        HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &ffd);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

            std::wstring fullPathW = dirPath + L"\\" + ffd.cFileName;
            char pathBuf[MAX_PATH] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, fullPathW.c_str(), -1, pathBuf, MAX_PATH, NULL, NULL);
            std::string fullPathA = pathBuf;

            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                ScanDirectoryForStreams(fullPathW, maxDepth - 1, detections);
            }
            else {
                CheckFileStreams(fullPathW, fullPathA, detections);
            }
        } while (FindNextFileW(hFind, &ffd));

        FindClose(hFind);
    }

    std::vector<NTFSArtifactDetection> ScanNTFSArtifacts() {
        std::vector<NTFSArtifactDetection> detections;

        // Scan %TEMP%
        WCHAR tempPath[MAX_PATH] = { 0 };
        if (GetTempPathW(MAX_PATH, tempPath)) {
            ScanDirectoryForStreams(tempPath, 2, detections);
        }

        // Scan Downloads
        PWSTR pDownloads = NULL;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &pDownloads))) {
            ScanDirectoryForStreams(pDownloads, 2, detections);
            CoTaskMemFree(pDownloads);
        }

        // Scan Desktop
        PWSTR pDesktop = NULL;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, NULL, &pDesktop))) {
            ScanDirectoryForStreams(pDesktop, 2, detections);
            CoTaskMemFree(pDesktop);
        }

        return detections;
    }
}
