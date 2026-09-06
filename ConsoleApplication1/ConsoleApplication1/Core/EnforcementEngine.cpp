#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "EnforcementEngine.hpp"
#include "SyscallEngine.hpp"
#include "PEParser.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <intrin.h>
#include <winhttp.h>
#include <winioctl.h>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")

namespace EnforcementEngine {

    // ------------------------------------------------------------------ SMBIOS Extraction
    struct RawSMBIOSData {
        BYTE  Used20CallingMethod;
        BYTE  SMBIOSMajorVersion;
        BYTE  SMBIOSMinorVersion;
        BYTE  DmiRevision;
        DWORD Length;
        BYTE  SMBIOSTableData[1];
    };

    struct SMBIOSHeader {
        BYTE Type;
        BYTE Length;
        WORD Handle;
    };

    static std::string ExtractSMBIOSString(const BYTE* pTableEnd, const BYTE* pStrStart, BYTE strIndex) {
        if (strIndex == 0) return "";
        const char* p = (const char*)pStrStart;
        BYTE curIndex = 1;
        while ((const BYTE*)p < pTableEnd && *p) {
            if (curIndex == strIndex) {
                return std::string(p);
            }
            p += strlen(p) + 1;
            curIndex++;
        }
        return "";
    }

    static void QuerySMBIOSInfo(std::string& outUUID, std::string& outMbSerial) {
        DWORD sig = 'RSMB';
        DWORD bufSize = GetSystemFirmwareTable(sig, 0, NULL, 0);
        if (bufSize == 0) return;

        std::vector<BYTE> buffer(bufSize, 0);
        if (GetSystemFirmwareTable(sig, 0, buffer.data(), bufSize) == 0) return;

        const RawSMBIOSData* smbios = (const RawSMBIOSData*)buffer.data();
        const BYTE* pTable = smbios->SMBIOSTableData;
        const BYTE* pEnd = pTable + smbios->Length;

        while (pTable + sizeof(SMBIOSHeader) <= pEnd) {
            const SMBIOSHeader* hdr = (const SMBIOSHeader*)pTable;
            if (hdr->Length < sizeof(SMBIOSHeader)) break;

            const BYTE* pStrStart = pTable + hdr->Length;

            // Type 1: System Information (contains UUID & Serial)
            if (hdr->Type == 1 && hdr->Length >= 0x19) {
                // UUID at offset 0x08 (16 bytes)
                const BYTE* uuid = pTable + 0x08;
                bool isAllZero = true;
                bool isAllFF = true;
                for (int i = 0; i < 16; i++) {
                    if (uuid[i] != 0x00) isAllZero = false;
                    if (uuid[i] != 0xFF) isAllFF = false;
                }

                if (!isAllZero && !isAllFF) {
                    char uuidBuf[64] = { 0 };
                    // Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
                    sprintf_s(uuidBuf, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                        uuid[3], uuid[2], uuid[1], uuid[0],
                        uuid[5], uuid[4],
                        uuid[7], uuid[6],
                        uuid[8], uuid[9],
                        uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
                    outUUID = uuidBuf;
                }

                BYTE serialIdx = pTable[0x07];
                std::string s = ExtractSMBIOSString(pEnd, pStrStart, serialIdx);
                if (!s.empty() && s != "None" && s != "Default string" && s != "To be filled by O.E.M.") {
                    outMbSerial = s;
                }
            }

            // Type 2: Baseboard / Motherboard Information
            if (hdr->Type == 2 && hdr->Length >= 0x08 && outMbSerial.empty()) {
                BYTE serialIdx = pTable[0x07];
                std::string s = ExtractSMBIOSString(pEnd, pStrStart, serialIdx);
                if (!s.empty() && s != "None" && s != "Default string" && s != "To be filled by O.E.M.") {
                    outMbSerial = s;
                }
            }

            // Advance past strings to next structure (ends with double null 0x00 0x00)
            const BYTE* pNext = pStrStart;
            while (pNext + 1 < pEnd && !(pNext[0] == 0 && pNext[1] == 0)) {
                pNext++;
            }
            pTable = pNext + 2;
        }
    }

    // ------------------------------------------------------------------ Disk Serial Extraction
    static std::string QueryDiskSerial() {
        HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hDisk == INVALID_HANDLE_VALUE) {
            hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        }
        if (hDisk == INVALID_HANDLE_VALUE) return "";

        STORAGE_PROPERTY_QUERY query = {};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;

        BYTE outBuf[1024] = { 0 };
        DWORD bytesReturned = 0;

        if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
            outBuf, sizeof(outBuf), &bytesReturned, NULL)) {
            PSTORAGE_DEVICE_DESCRIPTOR pDesc = (PSTORAGE_DEVICE_DESCRIPTOR)outBuf;
            if (pDesc->SerialNumberOffset > 0 && pDesc->SerialNumberOffset < bytesReturned) {
                const char* pSerial = (const char*)(outBuf + pDesc->SerialNumberOffset);
                std::string serial = pSerial;
                // Trim whitespace
                serial.erase(0, serial.find_first_not_of(" \t\r\n"));
                serial.erase(serial.find_last_not_of(" \t\r\n") + 1);
                CloseHandle(hDisk);
                return serial;
            }
        }

        CloseHandle(hDisk);
        return "";
    }

    // ------------------------------------------------------------------ GPU Identification
    static void QueryGPUInfo(std::string& outDesc, std::string& outPciId) {
        DISPLAY_DEVICEW dd = { sizeof(dd) };
        for (DWORD i = 0; EnumDisplayDevicesW(NULL, i, &dd, 0); i++) {
            if ((dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) || (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE)) {
                char descBuf[MAX_PATH] = { 0 };
                WideCharToMultiByte(CP_UTF8, 0, dd.DeviceString, -1, descBuf, MAX_PATH, NULL, NULL);
                outDesc = descBuf;

                char idBuf[MAX_PATH] = { 0 };
                WideCharToMultiByte(CP_UTF8, 0, dd.DeviceID, -1, idBuf, MAX_PATH, NULL, NULL);
                outPciId = idBuf;
                break;
            }
        }
    }

    // ------------------------------------------------------------------ CPU Identification
    static void QueryCPUInfo(std::string& outBrand, std::string& outProcId) {
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 0);
        int nExIds = cpuInfo[0];

        // CPU Brand String (0x80000002..0x80000004)
        __cpuid(cpuInfo, 0x80000000);
        unsigned int nExIdsMax = (unsigned int)cpuInfo[0];
        if (nExIdsMax >= 0x80000004) {
            char brand[64] = { 0 };
            __cpuid((int*)(brand), 0x80000002);
            __cpuid((int*)(brand + 16), 0x80000003);
            __cpuid((int*)(brand + 32), 0x80000004);
            outBrand = brand;
            outBrand.erase(0, outBrand.find_first_not_of(" \t\r\n"));
            outBrand.erase(outBrand.find_last_not_of(" \t\r\n") + 1);
        }

        // Processor Signature / Features (0x1)
        __cpuid(cpuInfo, 1);
        char procIdBuf[32] = { 0 };
        sprintf_s(procIdBuf, "%08X-%08X", (unsigned int)cpuInfo[0], (unsigned int)cpuInfo[3]);
        outProcId = procIdBuf;
    }

    // ------------------------------------------------------------------ Public HWID Extractor
    SystemHWIDInfo GetSystemHWID() {
        SystemHWIDInfo info;

        QuerySMBIOSInfo(info.MotherboardUUID, info.MotherboardSerial);
        info.DiskSerial = QueryDiskSerial();
        QueryGPUInfo(info.GPUDescription, info.GPUPciId);
        QueryCPUInfo(info.CPUBrand, info.CPUProcessorId);

        // Build combined hardware seed string
        std::string rawSeed = "UUID=" + info.MotherboardUUID +
                              ";MBSERIAL=" + info.MotherboardSerial +
                              ";DISK=" + info.DiskSerial +
                              ";GPU=" + info.GPUPciId +
                              ";CPU=" + info.CPUProcessorId;

        std::string hash = PE::PEImage::ComputeSHA256((const BYTE*)rawSeed.data(), rawSeed.size());
        info.RawHWIDHash = hash;

        // Format into readable HWID token: HWID-XXXX-XXXX-XXXX-XXXX
        if (hash.size() >= 16) {
            info.CompositeHWID = "HWID-" +
                                 hash.substr(0, 4) + "-" +
                                 hash.substr(4, 4) + "-" +
                                 hash.substr(8, 4) + "-" +
                                 hash.substr(12, 4);
            std::transform(info.CompositeHWID.begin(), info.CompositeHWID.end(), info.CompositeHWID.begin(), ::toupper);
        }
        else {
            info.CompositeHWID = "HWID-UNKNOWN-GENERIC";
        }

        return info;
    }

    bool TerminateTargetProcess(DWORD processId, const std::string& reason) {
        if (processId == 0 || processId == GetCurrentProcessId()) return false;

        std::cout << "\033[91m[🚨 ENFORCEMENT ACTION] Terminating PID " << processId 
                  << " immediately! Reason: " << reason << "\033[0m\n";

        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
        if (hProcess) {
            // Exit code 0xC0000022 (STATUS_ACCESS_DENIED)
            BOOL success = TerminateProcess(hProcess, 0xC0000022);
            CloseHandle(hProcess);
            if (success) {
                std::cout << "\033[92m[+] SUCCESS: Process " << processId << " killed via TerminateProcess.\033[0m\n";
                return true;
            }
        }

        std::cout << "[-] Failed to open PID " << processId << " with PROCESS_TERMINATE (Error: " << GetLastError() << ")\n";
        return false;
    }

    bool EnforceHVCIPolicy(bool strictBlock, std::string& outMessage) {
        HKEY hKey;
        DWORD hvciEnabled = 0;
        DWORD dataSize = sizeof(DWORD);

        LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
            L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", 
            0, KEY_READ, &hKey);

        if (status == ERROR_SUCCESS) {
            RegQueryValueExW(hKey, L"Enabled", NULL, NULL, (LPBYTE)&hvciEnabled, &dataSize);
            RegCloseKey(hKey);
        }

        if (hvciEnabled == 1) {
            outMessage = "HVCI (Core Isolation / Memory Integrity) is ACTIVE and enforcing kernel code integrity.";
            return true;
        }

        outMessage = "CRITICAL SECURITY WARNING: HVCI (Memory Integrity) is DISABLED!\n"
                     "Your system is vulnerable to Kernel Driver Swapping (MDL overwrite) attacks.\n"
                     "Please enable 'Core Isolation -> Memory Integrity' in Windows Security Settings and restart your PC.";

        if (strictBlock) {
            return false;
        }
        return true;
    }

    static bool ParseUrl(const std::string& url, std::wstring& host, std::wstring& path, INTERNET_PORT& port, bool& isHttps) {
        std::string s = url;
        isHttps = false;
        port = INTERNET_DEFAULT_HTTP_PORT;

        if (s.rfind("https://", 0) == 0) {
            isHttps = true;
            port = INTERNET_DEFAULT_HTTPS_PORT;
            s = s.substr(8);
        }
        else if (s.rfind("http://", 0) == 0) {
            isHttps = false;
            port = INTERNET_DEFAULT_HTTP_PORT;
            s = s.substr(7);
        }

        size_t slashPos = s.find('/');
        std::string hostStr;
        std::string pathStr;

        if (slashPos != std::string::npos) {
            hostStr = s.substr(0, slashPos);
            pathStr = s.substr(slashPos);
        }
        else {
            hostStr = s;
            pathStr = "/";
        }

        size_t colonPos = hostStr.find(':');
        if (colonPos != std::string::npos) {
            port = (INTERNET_PORT)std::stoi(hostStr.substr(colonPos + 1));
            hostStr = hostStr.substr(0, colonPos);
        }

        WCHAR hostBuf[256] = { 0 };
        WCHAR pathBuf[1024] = { 0 };
        MultiByteToWideChar(CP_UTF8, 0, hostStr.c_str(), -1, hostBuf, 256);
        MultiByteToWideChar(CP_UTF8, 0, pathStr.c_str(), -1, pathBuf, 1024);

        host = hostBuf;
        path = pathBuf;
        return !host.empty();
    }

    bool DispatchBanTelemetry(const std::string& webhookUrl, const std::string& jsonDossier, const std::string& apiKey) {
        if (webhookUrl.empty() || jsonDossier.empty()) return false;

        std::wstring host, path;
        INTERNET_PORT port;
        bool isHttps;

        if (!ParseUrl(webhookUrl, host, path, port, isHttps)) {
            std::cout << "[-] Invalid Ban Webhook URL format: " << webhookUrl << "\n";
            return false;
        }

        HINTERNET hSession = WinHttpOpen(L"AntiCheat-Enforcement-Engine/3.0", 
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }

        DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), 
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        std::wstring headers = L"Content-Type: application/json\r\n";
        if (!apiKey.empty()) {
            WCHAR keyBuf[256] = { 0 };
            MultiByteToWideChar(CP_UTF8, 0, apiKey.c_str(), -1, keyBuf, 256);
            headers += L"X-AC-Authorization: " + std::wstring(keyBuf) + L"\r\n";
        }

        BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(), 
            (LPVOID)jsonDossier.c_str(), (DWORD)jsonDossier.length(), (DWORD)jsonDossier.length(), 0);

        if (bResults) {
            bResults = WinHttpReceiveResponse(hRequest, NULL);
        }

        if (bResults) {
            DWORD statusCode = 0;
            DWORD statusSize = sizeof(statusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, 
                WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);

            std::cout << "\033[92m[+] Ban Telemetry Transmitted to Server! HTTP Status: " << statusCode << "\033[0m\n";
        }
        else {
            std::cout << "[-] Warning: Failed to send ban telemetry (Error: " << GetLastError() << ")\n";
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return (bResults == TRUE);
    }

    EnforcementResult ProcessCriticalAlerts(DWORD gamePid, DWORD cheatPid, const std::string& reason, const EnforcementConfig& config, const std::string& jsonEvidencePath) {
        EnforcementResult res;
        res.TargetHWID = GetSystemHWID();
        res.ActionSummary = "Triggered enforcement for: " + reason + " | Target HWID: " + res.TargetHWID.CompositeHWID;

        if (config.AutoKillEnabled) {
            if (cheatPid > 0 && cheatPid != gamePid) {
                res.TerminatedCheat = TerminateTargetProcess(cheatPid, "Cheat Injector / External Handle Bridge (" + reason + ")");
            }
            if (gamePid > 0) {
                res.TerminatedGame = TerminateTargetProcess(gamePid, "Integrity Compromised: " + reason);
                res.TerminatedPid = gamePid;
            }
        }

        if (!config.BanWebhookUrl.empty()) {
            std::ifstream jsonFile(jsonEvidencePath);
            std::string payloadJson;
            if (jsonFile.is_open()) {
                std::stringstream buffer;
                buffer << jsonFile.rdbuf();
                jsonFile.close();
                payloadJson = buffer.str();
            }
            else {
                // Synthesize JSON payload with HWID if file not ready
                payloadJson = "{\"reason\":\"" + reason + "\",\"hwid\":\"" + res.TargetHWID.CompositeHWID +
                              "\",\"disk_serial\":\"" + res.TargetHWID.DiskSerial +
                              "\",\"motherboard_uuid\":\"" + res.TargetHWID.MotherboardUUID +
                              "\",\"gpu\":\"" + res.TargetHWID.GPUDescription + "\"}";
            }
            res.TelemetrySent = DispatchBanTelemetry(config.BanWebhookUrl, payloadJson, config.ServerApiKey);
        }

        return res;
    }
}
