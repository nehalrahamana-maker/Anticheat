#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace EncryptedStringScanner {

    // Classification of the obfuscation technique found
    enum class ObfuscationType {
        XOR_ENCRYPTED_STRING,      // XOR key-encrypted string that decodes to a cheat keyword
        RC4_KEYSTREAM_STUB,        // RC4 S-box initialisation pattern (256-byte permutation)
        BASE64_ENCODED_PAYLOAD,    // Base64-encoded data in memory that decodes to a PE or URL
        ROT_ENCODED_STRING,        // ROT-N (typically ROT-13 or ROT-47) encoded cheat string
        WIDE_CHAR_OBFUSCATED,      // Wide-string character obfuscation (each char ±N)
        STACK_STRING_PUSH_SEQUENCE // Compiler-generated push-dword sequences spelling a string
    };

    struct EncryptedStringDetection {
        DWORD       ProcessId = 0;
        std::string ProcessName;

        ULONG_PTR   AddressInMemory = 0; // VA where the pattern was found
        SIZE_T      RegionSize      = 0; // Size of the enclosing memory region

        ObfuscationType ObfType;
        std::string ObfTypeName;   // Human-readable name

        // The plaintext result after decryption / decoding (truncated to 256 chars)
        std::string DecodedString;

        // Raw bytes at detection site (first 32 bytes)
        std::vector<BYTE> RawBytes;

        // "CRITICAL" for confirmed cheat string, "HIGH" for suspicious pattern
        std::string Severity;
        std::string Description;
    };

    // Scan a specific process for obfuscated / encrypted cheat strings in memory
    std::vector<EncryptedStringDetection> ScanProcessEncryptedStrings(DWORD pid, const std::string& procName);

    // Scan all running processes
    std::vector<EncryptedStringDetection> ScanAllProcessesEncryptedStrings();

} // namespace EncryptedStringScanner
