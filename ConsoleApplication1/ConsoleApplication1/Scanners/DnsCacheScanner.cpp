// DnsCacheScanner.cpp
// Queries the Windows DNS resolver cache via DnsGetCacheDataTable()
// and flags entries matching known cheat C2 domains, download hosts,
// and domains with cheat-related substrings.
//
// The DNS cache persists until the machine reboots or the cache is
// flushed — making it a useful short-term forensic artifact.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "DnsCacheScanner.hpp"
#include <windns.h>
#include <algorithm>

#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace DnsCacheScanner {

    // =========================================================================
    // Known cheat infrastructure domains (C2, CDNs, download hosts)
    // =========================================================================
    static const char* k_KnownCheatDomains[] = {
        // Cheat loader / C2 patterns
        "cheat.ninja", "cheat.gg", "cheat.codes", "uc-forum.com",
        "unknowncheats.me", "uc-hacks.com", "mpgh.net", "hackforums.net",
        "elitepvpers.com", "leakforums.net", "nulledbb.com", "cracked.io",
        // FiveM cheat sites
        "fivemhacks.com", "fivemcheats.net", "fivem-cheat.com",
        "flk-bypass.com", "flkbypass.net", "anti-echo.com",
        // Siege cheat sites
        "r6hacks.com", "siegehacks.net", "crusadercheat.com",
        // Fortnite cheat sites
        "fortnitecheats.net", "fortnite-hack.com",
        // Minecraft cheat clients
        "novaclient.net", "grimclient.com",
        // Generic cheat infrastructure
        "bypass.fun", "hxcheats.com", "venacy.gg", "hdplayer.cc",
        "hddplayer.net", "gva-client.com", "galib.net", "garv.cc",
        "bstkvmm.com", "hiddenxcheat.com", "hiddenx.gg",
        // Spoofer / cleaner sites
        "hwid-spoofer.com", "spoofer.cc", "hwidspoof.net",
        // DMA / FPGA
        "pcileech.com", "dma-cheat.com",
        nullptr
    };

    // Cheat-related substrings in hostnames
    static const char* k_DomainKeywords[] = {
        "aimbot", "wallhack", "cheat", "hack", "inject", "bypass",
        "spoof", "dumper", "triggerbot", "silentaim", "norecoil",
        "hdplayer", "hddplayer", "galib", "gva", "garv", "bstkvmm",
        "kdmapper", "xenos", "externhack", "externalmem",
        "crusader", "hydron", "vega", "ring1cheat",
        nullptr
    };

    // Legitimate domains to never flag (whitelist)
    static const char* k_DomainWhitelist[] = {
        "microsoft.com", "windows.com", "windowsupdate.com",
        "google.com", "googleapis.com", "gstatic.com",
        "cloudflare.com", "amazon.com", "amazonaws.com",
        "discord.com", "discordapp.com", "steam.com", "steampowered.com",
        "epicgames.com", "nvidia.com", "amd.com",
        "github.com", "githubusercontent.com",
        "riotgames.com", "battlenet.com", "blizzard.com",
        "ubisoft.com", "ea.com", "origin.com",
        "faceit.com", "esea.net", "eac.gg",
        nullptr
    };

    static std::string ToLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }

    static bool IsWhitelisted(const std::string& lower) {
        for (int i = 0; k_DomainWhitelist[i]; i++)
            if (lower.find(k_DomainWhitelist[i]) != std::string::npos) return true;
        return false;
    }

    static bool IsKnownCheatDomain(const std::string& lower, std::string& reason) {
        for (int i = 0; k_KnownCheatDomains[i]; i++) {
            if (lower.find(k_KnownCheatDomains[i]) != std::string::npos) {
                reason = std::string("Known cheat domain: ") + k_KnownCheatDomains[i];
                return true;
            }
        }
        return false;
    }

    static bool HasCheatKeyword(const std::string& lower, std::string& reason) {
        for (int i = 0; k_DomainKeywords[i]; i++) {
            if (lower.find(k_DomainKeywords[i]) != std::string::npos) {
                reason = std::string("Domain contains cheat keyword: ") + k_DomainKeywords[i];
                return true;
            }
        }
        return false;
    }

    static std::string RecordTypeStr(WORD type) {
        switch (type) {
        case DNS_TYPE_A:     return "A";
        case DNS_TYPE_AAAA:  return "AAAA";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_PTR:   return "PTR";
        case DNS_TYPE_MX:    return "MX";
        default: char buf[16]; sprintf_s(buf, "TYPE%u", type); return buf;
        }
    }

    // =========================================================================
    // Public API
    // =========================================================================
    std::vector<DnsEntry> ScanDnsCache() {
        std::vector<DnsEntry> results;

        // DnsGetCacheDataTable is an undocumented but stable API in dnsapi.dll
        typedef DNS_STATUS(WINAPI* pfnDnsGetCacheDataTable)(PDNS_RECORD*);
        HMODULE hDns = LoadLibraryW(L"dnsapi.dll");
        if (!hDns) return results;

        auto fnGetCache = (pfnDnsGetCacheDataTable)GetProcAddress(hDns, "DnsGetCacheDataTable");
        if (!fnGetCache) { FreeLibrary(hDns); return results; }

        PDNS_RECORD pRecords = nullptr;
        DNS_STATUS status = fnGetCache(&pRecords);
        FreeLibrary(hDns);

        if (status != ERROR_SUCCESS || !pRecords) return results;

        PDNS_RECORD pCur = pRecords;
        while (pCur) {
            if (pCur->pName) {
                char nameA[512] = {};
                // pName is PWSTR
                WideCharToMultiByte(CP_UTF8, 0, pCur->pName, -1, nameA, sizeof(nameA) - 1, NULL, NULL);
                std::string hostName(nameA);
                std::string lower = ToLower(hostName);

                if (!IsWhitelisted(lower)) {
                    std::string reason;
                    bool knownCheat = IsKnownCheatDomain(lower, reason);
                    bool hasKw      = !knownCheat && HasCheatKeyword(lower, reason);

                    if (knownCheat || hasKw) {
                        DnsEntry entry;
                        entry.HostName    = hostName;
                        entry.RecordType  = RecordTypeStr(pCur->wType);

                        // Extract data value
                        if (pCur->wType == DNS_TYPE_A) {
                            IN_ADDR addr;
                            addr.s_addr = pCur->Data.A.IpAddress;
                            entry.DataValue = inet_ntoa(addr);
                        } else if (pCur->wType == DNS_TYPE_CNAME && pCur->Data.CNAME.pNameHost) {
                            char cnameA[256] = {};
                            WideCharToMultiByte(CP_UTF8, 0, pCur->Data.CNAME.pNameHost, -1,
                                                cnameA, sizeof(cnameA) - 1, NULL, NULL);
                            entry.DataValue = cnameA;
                        }

                        entry.IsCheatDomain   = true;
                        entry.MatchedReason   = reason;
                        entry.ConfidenceScore = knownCheat ? 88 : 70;
                        entry.Severity        = knownCheat ? "CRITICAL" : "HIGH";
                        entry.Description     = "[DNS_CACHE] Host \"" + hostName +
                                                "\" resolved — " + reason +
                                                ". Record type: " + entry.RecordType;
                        results.push_back(entry);
                    }
                }
            }
            pCur = pCur->pNext;
        }

        DnsRecordListFree(pRecords, DnsFreeRecordList);
        return results;
    }

} // namespace DnsCacheScanner
