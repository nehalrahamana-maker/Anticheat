// EncryptedStringScanner.cpp
// Scans process memory for obfuscated / encrypted cheat-related strings.
// Techniques detected:
//   1. XOR single-byte key brute-force: tries all 255 keys against each
//      candidate byte run; checks result against cheat keyword dictionary.
//   2. RC4 S-box initialisation pattern (0..255 permutation).
//   3. Base64 blobs that decode to a PE header (MZ) or http:// URL.
//   4. ROT-13/ROT-47 encoded strings matching cheat keywords.
//   5. Wide-char obfuscation (each char = real_char ± constant).
//
// Only private (MEM_PRIVATE) executable or suspicious read-write regions are
// scanned to keep CPU cost low and false-positives near zero.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "EncryptedStringScanner.hpp"
#include "SyscallEngine.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <algorithm>
#include <cmath>
#include <set>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

namespace EncryptedStringScanner {

    // ------------------------------------------------------------------ keyword list
    // Keep this tight — every entry must be unambiguously cheat-related.
    static const std::vector<std::string> k_CheatKeywords = {
        "cruz", "renault", "finalexp", "speedhack", "aimbot", "wallhack",
        "triggerbot", "redeye", "red-eye", "xenos", "cheatengine", "kdmapper",
        "blackbone", "winverb", "zwswap", "rawdriver", "extremeinject",
        "injector", "bypass", "spoofer", "dumper", "kdu.exe", "maphack",
        "noRecoil", "norecoil", "silentaim", "silent_aim", "memread",
        "readmem", "vmread", "gvaclient", "gva_client", "externalmem",
        "hdplayercheat", "bluestackscheat", "pubgmhack", "bgmihack"
    };

    static std::string ToLower(const std::string& s) {
        std::string r = s; std::transform(r.begin(), r.end(), r.begin(), ::tolower); return r;
    }

    static bool ContainsCheatKeyword(const std::string& text) {
        std::string lower = ToLower(text);
        for (const auto& kw : k_CheatKeywords)
            if (lower.find(kw) != std::string::npos) return true;
        return false;
    }

    // ------------------------------------------------------------------ Base64 decoder
    static std::vector<BYTE> Base64Decode(const BYTE* data, size_t len) {
        static const char* b64 =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::vector<BYTE> out;
        out.reserve(len * 3 / 4 + 4);
        int val = 0, bits = -8;
        for (size_t i = 0; i < len; i++) {
            char c = (char)data[i];
            if (c == '=') break;
            const char* p = strchr(b64, c);
            if (!p) { bits = -8; val = 0; continue; } // reset on invalid
            val = (val << 6) | (int)(p - b64);
            bits += 6;
            if (bits >= 0) {
                out.push_back((BYTE)((val >> bits) & 0xFF));
                bits -= 8;
            }
        }
        return out;
    }

    // ------------------------------------------------------------------ ROT-N decoder
    static std::string RotDecode(const BYTE* data, size_t len, int n) {
        std::string result;
        result.reserve(len);
        for (size_t i = 0; i < len; i++) {
            char c = (char)data[i];
            if (c >= 'A' && c <= 'Z') c = (char)('A' + (c - 'A' + n) % 26);
            else if (c >= 'a' && c <= 'z') c = (char)('a' + (c - 'a' + n) % 26);
            result += c;
        }
        return result;
    }

    // ------------------------------------------------------------------ RC4 S-box detector
    // A properly initialised RC4 S-box is a permutation of 0..255.
    static bool IsRC4SBox(const BYTE* buf, size_t len) {
        if (len < 256) return false;
        bool seen[256] = {};
        for (int i = 0; i < 256; i++) {
            BYTE v = buf[i];
            if (seen[v]) return false;
            seen[v] = true;
        }
        // Must NOT be the identity 0,1,2,…255 (uninitialised buffer)
        int identity = 0;
        for (int i = 0; i < 256; i++) if (buf[i] == (BYTE)i) identity++;
        return identity < 250; // allow a few coincidences
    }

    // ------------------------------------------------------------------ Shannon entropy
    static double CalculateShannonEntropy(const BYTE* data, size_t len) {
        if (len == 0) return 0.0;
        size_t counts[256] = { 0 };
        for (size_t i = 0; i < len; i++) counts[data[i]]++;
        double entropy = 0.0;
        for (int i = 0; i < 256; i++) {
            if (counts[i] > 0) {
                double p = (double)counts[i] / (double)len;
                entropy -= p * (log2(p));
            }
        }
        return entropy;
    }

    // ------------------------------------------------------------------ wide-char obfuscation
    // Each wide char = plaintext_char + delta. Try deltas 1..31.
    static std::string TryWideObf(const BYTE* buf, size_t byteLen) {
        if (byteLen < 12 || (byteLen & 1)) return {};
        size_t wlen = byteLen / 2;
        const WCHAR* wbuf = reinterpret_cast<const WCHAR*>(buf);

        for (int delta = 1; delta <= 31; delta++) {
            std::string decoded;
            decoded.reserve(wlen);
            for (size_t i = 0; i < wlen; i++) {
                WCHAR wc = wbuf[i] - (WCHAR)delta;
                if (wc < 0x20 || wc > 0x7E) { decoded.clear(); break; }
                decoded += (char)wc;
            }
            if (decoded.size() >= 5 && ContainsCheatKeyword(decoded))
                return decoded;
        }
        return {};
    }

    // ------------------------------------------------------------------ processes to skip
    static bool IsWhitelistedProcess(const std::string& lowerName) {
        static const char* wl[] = {
            "chrome", "msedge", "firefox", "opera", "brave",
            "code.exe", "devenv.exe", "clangd", "msbuild",
            "antimalware", "defender", "svchost", "csrss",
            "lsass", "services", "smss", "wininit", "winlogon",
            "dwm.exe", "explorer.exe", "runtimebroker", "sihost",
            "conhost", "taskhostw", "spoolsv", "audiodg", "searchhost",
            "systemsettings", "antigravity", nullptr
        };
        for (int i = 0; wl[i]; i++)
            if (lowerName.find(wl[i]) != std::string::npos) return true;
        return false;
    }

    // ------------------------------------------------------------------ scan a memory region
    static void ScanRegion(HANDLE hProc,
                           DWORD pid,
                           const std::string& procName,
                           ULONG_PTR base,
                           SIZE_T regSize,
                           std::vector<EncryptedStringDetection>& out,
                           std::set<ULONG_PTR>& seenAddresses) {

        // Cap region reads at 256 KB to keep scan instant
        const SIZE_T kMaxRead = 256 * 1024;
        SIZE_T readSize = (regSize < kMaxRead) ? regSize : kMaxRead;

        std::vector<BYTE> buf(readSize, 0);
        SIZE_T bytesRead = 0;
        NTSTATUS st = SyscallEngine::DirectNtReadVirtualMemory(
            hProc, (PVOID)base, buf.data(), readSize, &bytesRead);
        if (!NT_SUCCESS(st) || bytesRead < 32) return;
        buf.resize(bytesRead);

        const size_t kMinStringLen = 6;
        const size_t kMaxStringLen = 256;
        const size_t kSlidStep     = 32; // stride between sliding-window positions

        for (size_t offset = 0; offset + kMinStringLen < bytesRead; offset += kSlidStep) {

            ULONG_PTR addr = base + offset;
            if (seenAddresses.count(addr)) continue;

            // Compute Shannon entropy for a 32-byte candidate window
            size_t windowLen = (std::min)((size_t)32, bytesRead - offset);
            double entropy = CalculateShannonEntropy(buf.data() + offset, windowLen);

            // ------- 1. Entropy-Filtered XOR brute-force -------
            // Only examine windows with text-like or encrypted string entropy (2.5 <= entropy <= 7.80)
            if (entropy >= 2.5 && entropy <= 7.80) {
                for (BYTE k = 1; k != 0; k++) { // k loops 1..255
                    std::string decoded;
                    decoded.reserve(kMaxStringLen);
                    for (size_t j = offset; j < bytesRead && decoded.size() < kMaxStringLen; j++) {
                        char c = (char)(buf[j] ^ k);
                        if (c >= 0x20 && c <= 0x7E) decoded += c;
                        else break;
                    }
                    if (decoded.size() >= kMinStringLen && ContainsCheatKeyword(decoded)) {
                        seenAddresses.insert(addr);
                        EncryptedStringDetection d;
                        d.ProcessId     = pid;
                        d.ProcessName   = procName;
                        d.AddressInMemory = addr;
                        d.RegionSize    = regSize;
                        d.ObfType       = ObfuscationType::XOR_ENCRYPTED_STRING;
                        d.ObfTypeName   = "XOR_ENCRYPTED_STRING (key=0x" +
                                          [&]{ char tmp[8]; sprintf_s(tmp, "%02X", k); return std::string(tmp); }() + ")";
                        d.DecodedString = decoded;
                        d.RawBytes.assign(buf.begin() + offset,
                                          buf.begin() + offset + (std::min)((size_t)32, bytesRead - offset));
                        d.Severity      = "CRITICAL";
                        d.Description   = "XOR-encrypted cheat string (key 0x" +
                                          [&]{ char tmp[8]; sprintf_s(tmp, "%02X", k); return std::string(tmp); }() +
                                          ", Entropy: " + [&]{ char tmp[16]; sprintf_s(tmp, "%.2f", entropy); return std::string(tmp); }() +
                                          ") decoded to: \"" + decoded + "\" in PID " +
                                          std::to_string(pid) + " at 0x" +
                                          [&]{ char tmp[32]; sprintf_s(tmp, "%llX", (unsigned long long)addr); return std::string(tmp); }();
                        out.push_back(d);
                        goto next_offset;
                    }
                }
            }

            // ------- 2. RC4 S-box -------
            if (offset + 256 <= bytesRead && IsRC4SBox(buf.data() + offset, bytesRead - offset)) {
                seenAddresses.insert(addr);
                EncryptedStringDetection d;
                d.ProcessId     = pid;
                d.ProcessName   = procName;
                d.AddressInMemory = addr;
                d.RegionSize    = regSize;
                d.ObfType       = ObfuscationType::RC4_KEYSTREAM_STUB;
                d.ObfTypeName   = "RC4_S-BOX_PERMUTATION";
                d.DecodedString = "(RC4 cipher state — payload decrypts at runtime)";
                d.RawBytes.assign(buf.begin() + offset,
                                  buf.begin() + offset + std::min((size_t)32, bytesRead - offset));
                d.Severity      = "HIGH";
                d.Description   = "256-byte RC4 S-box permutation found in private memory at 0x" +
                                  [&]{ char tmp[32]; sprintf_s(tmp, "%llX", (unsigned long long)addr); return std::string(tmp); }() +
                                  ". Indicates runtime decryption of payload or strings.";
                out.push_back(d);
                goto next_offset;
            }

            // ------- 3. Base64 blob -------
            {
                static const auto isB64 = [](BYTE c) {
                    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
                };
                size_t runLen = 0;
                while (offset + runLen < bytesRead && isB64(buf[offset + runLen])) runLen++;
                if (runLen >= 32) {
                    auto decoded = Base64Decode(buf.data() + offset, runLen);
                    bool isMZ = decoded.size() >= 2 && decoded[0] == 'M' && decoded[1] == 'Z';
                    std::string dstr(decoded.begin(), decoded.end());
                    bool isUrl = dstr.find("http://") != std::string::npos ||
                                 dstr.find("https://") != std::string::npos;
                    bool hasKw = ContainsCheatKeyword(dstr);
                    if (isMZ || isUrl || hasKw) {
                        seenAddresses.insert(addr);
                        EncryptedStringDetection d;
                        d.ProcessId      = pid;
                        d.ProcessName    = procName;
                        d.AddressInMemory = addr;
                        d.RegionSize     = regSize;
                        d.ObfType        = ObfuscationType::BASE64_ENCODED_PAYLOAD;
                        d.ObfTypeName    = "BASE64_ENCODED_PAYLOAD";
                        d.DecodedString  = isMZ ? "(MZ PE header — encoded executable)" :
                                           (isUrl ? dstr.substr(0, 128) : dstr.substr(0, 128));
                        d.RawBytes.assign(buf.begin() + offset,
                                          buf.begin() + offset + (std::min)((size_t)32, bytesRead - offset));
                        d.Severity       = isMZ ? "CRITICAL" : "HIGH";
                        d.Description    = std::string("Base64-encoded ") +
                                           (isMZ ? "PE payload" : (isUrl ? "URL" : "cheat string")) +
                                           " found at 0x" +
                                           [&]{ char tmp[32]; sprintf_s(tmp, "%llX", (unsigned long long)addr); return std::string(tmp); }();
                        out.push_back(d);
                        goto next_offset;
                    }
                }
            }

            // ------- 4. ROT-13 / ROT-47 -------
            {
                size_t runLen = 0;
                while (offset + runLen < bytesRead) {
                    BYTE c = buf[offset + runLen];
                    if (c >= 0x20 && c <= 0x7E) runLen++;
                    else break;
                    if (runLen >= kMaxStringLen) break;
                }
                if (runLen >= kMinStringLen) {
                    std::string rot13 = RotDecode(buf.data() + offset, runLen, 13);
                    std::string rot47;
                    for (size_t i = 0; i < runLen; i++) {
                        BYTE c = buf[offset + i];
                        if (c >= 33 && c <= 126) rot47 += (char)(33 + (c - 33 + 47) % 94);
                        else rot47 += (char)c;
                    }
                    bool r13 = ContainsCheatKeyword(rot13);
                    bool r47 = ContainsCheatKeyword(rot47);
                    if (r13 || r47) {
                        seenAddresses.insert(addr);
                        EncryptedStringDetection d;
                        d.ProcessId      = pid;
                        d.ProcessName    = procName;
                        d.AddressInMemory = addr;
                        d.RegionSize     = regSize;
                        d.ObfType        = ObfuscationType::ROT_ENCODED_STRING;
                        d.ObfTypeName    = r13 ? "ROT-13_ENCODED_STRING" : "ROT-47_ENCODED_STRING";
                        d.DecodedString  = r13 ? rot13 : rot47;
                        d.RawBytes.assign(buf.begin() + offset,
                                          buf.begin() + offset + (std::min)((size_t)32, bytesRead - offset));
                        d.Severity       = "HIGH";
                        d.Description    = "ROT-encoded cheat string decoded to: \"" +
                                           d.DecodedString + "\" in PID " + std::to_string(pid);
                        out.push_back(d);
                        goto next_offset;
                    }
                }
            }

            // ------- 5. Wide-char obfuscation -------
            if (offset + 12 <= bytesRead) {
                std::string wdec = TryWideObf(buf.data() + offset,
                                              (std::min)((size_t)128, bytesRead - offset));
                if (!wdec.empty()) {
                    seenAddresses.insert(addr);
                    EncryptedStringDetection d;
                    d.ProcessId     = pid;
                    d.ProcessName   = procName;
                    d.AddressInMemory = addr;
                    d.RegionSize    = regSize;
                    d.ObfType       = ObfuscationType::WIDE_CHAR_OBFUSCATED;
                    d.ObfTypeName   = "WIDE_CHAR_DELTA_OBFUSCATION";
                    d.DecodedString = wdec;
                    d.RawBytes.assign(buf.begin() + offset,
                                      buf.begin() + offset + (std::min)((size_t)32, bytesRead - offset));
                    d.Severity      = "HIGH";
                    d.Description   = "Wide-character delta-obfuscated cheat string: \"" +
                                      wdec + "\" found in PID " + std::to_string(pid);
                    out.push_back(d);
                    goto next_offset;
                }
            }

            next_offset:;
        }
    }

    // ------------------------------------------------------------------ per-process

    std::vector<EncryptedStringDetection> ScanProcessEncryptedStrings(DWORD pid, const std::string& procName) {
        std::vector<EncryptedStringDetection> detections;

        std::string lowerProc = procName;
        std::transform(lowerProc.begin(), lowerProc.end(), lowerProc.begin(), ::tolower);
        if (IsWhitelistedProcess(lowerProc)) return detections;

        HANDLE hProc = NULL;
        OBJECT_ATTRIBUTES_EX objAttr = { sizeof(OBJECT_ATTRIBUTES_EX) };
        CLIENT_ID_EX cid = { (HANDLE)(ULONG_PTR)pid, NULL };

        NTSTATUS st = SyscallEngine::DirectNtOpenProcess(
            &hProc, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, &objAttr, &cid);
        if (!NT_SUCCESS(st) || !hProc)
            hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) return detections;

        MEMORY_BASIC_INFORMATION mbi = {};
        ULONG_PTR addr = 0x10000;
        SIZE_T retLen = 0;
        std::set<ULONG_PTR> seenAddresses;

        const size_t kMaxDetectionsPerProc = 6;
        size_t regionsScanned = 0;

        while (NT_SUCCESS(SyscallEngine::DirectNtQueryVirtualMemory(
            hProc, (PVOID)addr, MemoryBasicInformationEx,
            &mbi, sizeof(mbi), &retLen)))
        {
            if (detections.size() >= kMaxDetectionsPerProc || regionsScanned >= 32) break;

            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
                // Focus on executable / RWX unbacked pages
                bool interesting =
                    (mbi.Protect == PAGE_EXECUTE_READWRITE) ||
                    (mbi.Protect == PAGE_EXECUTE_READ);

                if (interesting) {
                    regionsScanned++;
                    ScanRegion(hProc, pid, procName,
                               (ULONG_PTR)mbi.BaseAddress, mbi.RegionSize,
                               detections, seenAddresses);
                }
            }

            addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            if (addr >= 0x7FFFFFFF0000ULL || mbi.RegionSize == 0) break;
        }

        CloseHandle(hProc);
        return detections;
    }

    // ------------------------------------------------------------------ all processes

    std::vector<EncryptedStringDetection> ScanAllProcessesEncryptedStrings() {
        std::vector<EncryptedStringDetection> all;

        DWORD pids[1024] = {};
        DWORD needed = 0;
        if (!EnumProcesses(pids, sizeof(pids), &needed)) return all;

        DWORD count = needed / sizeof(DWORD);
        for (DWORD i = 0; i < count; i++) {
            DWORD pid = pids[i];
            if (pid <= 4) continue;

            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) continue;

            WCHAR szPath[MAX_PATH] = {};
            DWORD dwSz = MAX_PATH;
            QueryFullProcessImageNameW(h, 0, szPath, &dwSz);
            CloseHandle(h);

            WCHAR* pName = PathFindFileNameW(szPath);
            char nameBuf[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pName, -1, nameBuf, MAX_PATH, NULL, NULL);

            std::string lowerName = nameBuf;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
            if (IsWhitelistedProcess(lowerName)) continue;

            auto dets = ScanProcessEncryptedStrings(pid, nameBuf);
            if (!dets.empty()) {
                all.insert(all.end(), dets.begin(), dets.end());
            }
        }
        return all;
    }

} // namespace EncryptedStringScanner
