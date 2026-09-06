#include "SigScanner.hpp"
#include "PEParser.hpp"
#include <psapi.h>
#include <shlwapi.h>
#include <iostream>
#include <algorithm>

namespace SigScanner {

    SignatureDetection ScanBinarySignature(const std::wstring& filePath) {
        SignatureDetection det;
        det.FilePath = filePath;
        WCHAR* pFile = PathFindFileNameW(filePath.c_str());
        char nameBuf[MAX_PATH] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, pFile, -1, nameBuf, MAX_PATH, NULL, NULL);
        det.FileName = nameBuf;
        det.HasCertTable = false;
        det.IsTrusted = false;
        det.IsForgedMicrosoftCert = false;
        det.Severity = "CLEAN";
        det.Description = "Valid or Unsigned binary.";

        PE::PEImage pe;
        if (!pe.LoadFromFile(filePath)) {
            det.Severity = "MEDIUM";
            det.Description = "Unable to parse PE headers.";
            return det;
        }

        det.FileSHA256 = PE::PEImage::ComputeSHA256(pe.GetRawBuffer());

        auto certInfo = pe.ParseCertificate(filePath);
        det.HasCertTable = certInfo.HasCertificate;
        det.SecurityDirOffset = certInfo.VirtualAddress;
        det.SecurityDirSize = certInfo.Size;
        det.IsTrusted = certInfo.IsTrusted;
        det.WinTrustStatus = certInfo.WinTrustError;
        det.SignerSubject = certInfo.SubjectName;
        det.SignerIssuer = certInfo.IssuerName;

        bool isWindowsDirectory = (filePath.find(L"C:\\Windows\\") == 0);

        if (det.HasCertTable) {
            if (certInfo.WinTrustError == (DWORD)0x80096010L) { // TRUST_E_BAD_DIGEST
                det.IsForgedMicrosoftCert = true;
                det.Severity = "CRITICAL";
                det.Description = "FORGED SIGNATURE DETECTED! Digest mismatch (TRUST_E_BAD_DIGEST). Certificate block was copied from another binary onto this file.";
            }
            else if (!certInfo.IsTrusted && certInfo.IsMicrosoftSigned && !isWindowsDirectory) {
                det.IsForgedMicrosoftCert = true;
                det.Severity = "CRITICAL";
                det.Description = "FORGED MICROSOFT CERTIFICATE! File claims Microsoft origin ('" + certInfo.SubjectName + "') outside Windows directory with invalid trust chain.";
            }
            else if (!certInfo.IsTrusted && certInfo.WinTrustError != 0) {
                det.Severity = "HIGH";
                char errHex[32];
                sprintf_s(errHex, "0x%08X", certInfo.WinTrustError);
                det.Description = "Untrusted / Invalid Authenticode Signature (Error: " + std::string(errHex) + "). Signer: " + certInfo.SubjectName;
            }
            else if (certInfo.IsTrusted) {
                det.Severity = "CLEAN";
                det.Description = "Valid Authenticode Signature. Signer: " + certInfo.SubjectName;
            }
        }
        else {
            det.Severity = "INFO";
            det.Description = "Binary is unsigned (no Certificate Table present).";
        }

        return det;
    }

    static void ScanDirectoryRecursiveInternal(const std::wstring& dir, std::vector<SignatureDetection>& results) {
        std::wstring searchPattern = dir + L"\\*";
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) continue;

            std::wstring fullPath = dir + L"\\" + findData.cFileName;
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                ScanDirectoryRecursiveInternal(fullPath, results);
            }
            else {
                LPCWSTR ext = PathFindExtensionW(findData.cFileName);
                if (_wcsicmp(ext, L".exe") == 0 || _wcsicmp(ext, L".dll") == 0 || _wcsicmp(ext, L".sys") == 0) {
                    auto det = ScanBinarySignature(fullPath);
                    if (det.Severity == "CRITICAL" || det.Severity == "HIGH") {
                        results.push_back(det);
                    }
                }
            }
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
    }

    std::vector<SignatureDetection> ScanDirectorySignatures(const std::wstring& directoryPath) {
        std::vector<SignatureDetection> results;
        ScanDirectoryRecursiveInternal(directoryPath, results);
        return results;
    }

    std::vector<SignatureDetection> ScanRunningProcessesSignatures() {
        std::vector<SignatureDetection> results;
        std::vector<std::wstring> scannedPaths;

        DWORD pids[2048];
        DWORD cbNeeded;
        if (!EnumProcesses(pids, sizeof(pids), &cbNeeded)) return results;

        DWORD count = cbNeeded / sizeof(DWORD);
        for (DWORD i = 0; i < count; i++) {
            DWORD pid = pids[i];
            if (pid == 0 || pid == 4) continue;

            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) continue;

            WCHAR szPath[MAX_PATH] = { 0 };
            DWORD dwSize = MAX_PATH;
            if (QueryFullProcessImageNameW(h, 0, szPath, &dwSize)) {
                std::wstring wsPath(szPath);
                // Check if already scanned
                bool alreadyScanned = false;
                for (const auto& sp : scannedPaths) {
                    if (_wcsicmp(sp.c_str(), wsPath.c_str()) == 0) {
                        alreadyScanned = true;
                        break;
                    }
                }

                if (!alreadyScanned) {
                    scannedPaths.push_back(wsPath);
                    auto det = ScanBinarySignature(wsPath);
                    if (det.Severity == "CRITICAL" || det.Severity == "HIGH") {
                        results.push_back(det);
                    }
                }
            }
            CloseHandle(h);
        }

        return results;
    }
}
