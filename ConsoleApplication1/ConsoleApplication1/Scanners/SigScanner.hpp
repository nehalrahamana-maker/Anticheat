#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace SigScanner {

    struct SignatureDetection {
        std::wstring FilePath;
        std::string FileName;
        bool HasCertTable;
        DWORD SecurityDirOffset;
        DWORD SecurityDirSize;
        bool IsTrusted;
        DWORD WinTrustStatus;
        std::string SignerSubject;
        std::string SignerIssuer;
        std::string FileSHA256;
        bool IsForgedMicrosoftCert;
        std::string Severity; // "CRITICAL", "HIGH", "CLEAN"
        std::string Description;
    };

    // Scan a specific PE binary for signature forgery and digest tampering
    SignatureDetection ScanBinarySignature(const std::wstring& filePath);

    // Scan all binaries in a game directory or running process paths
    std::vector<SignatureDetection> ScanDirectorySignatures(const std::wstring& directoryPath);

    // Scan active running processes' main executables
    std::vector<SignatureDetection> ScanRunningProcessesSignatures();
}
