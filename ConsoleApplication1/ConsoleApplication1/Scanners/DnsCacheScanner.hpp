#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace DnsCacheScanner {

    struct DnsEntry {
        std::string  HostName;
        std::string  RecordType;    // "A", "AAAA", "CNAME", etc.
        std::string  DataValue;     // Resolved IP or CNAME target
        bool         IsCheatDomain  = false;
        std::string  MatchedReason;
        int          ConfidenceScore = 0;
        std::string  Severity;
        std::string  Description;
    };

    // Query live DNS resolver cache and flag cheat-related domains
    std::vector<DnsEntry> ScanDnsCache();

} // namespace DnsCacheScanner
