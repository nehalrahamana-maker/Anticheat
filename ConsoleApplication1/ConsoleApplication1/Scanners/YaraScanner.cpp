// YaraScanner.cpp
// High-Performance Native YARA Scanning Engine for Anti-Cheat
// Supports:
//   1. Built-in real-world rule sets (Aimbots, Emulators, Bypasses, Drivers, Injectors, Forensics)
//   2. Dynamic parsing & loading of external .yar / .yara files (Aggregated 37k+ line rules)
//   3. High-throughput memory scanning of running processes (MEM_COMMIT / MEM_PRIVATE)
//   4. Ultra-fast scanning of dropped files & system artifacts

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "YaraScanner.hpp"
#include "../Core/SyscallEngine.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <cctype>
#include <mutex>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

namespace YaraScanner {

    static std::vector<YaraRule> s_Rules;
    static std::mutex s_RulesMutex;
    static bool s_Initialized = false;

    // Fast case-insensitive string conversion
    static std::string ToLower(const std::string& str) {
        std::string res = str;
        std::transform(res.begin(), res.end(), res.begin(), [](unsigned char c) {
            return (char)::tolower(c);
        });
        return res;
    }

    // Process whitelist (system & developer processes to avoid overhead/FPs)
    static const char* k_YaraWhitelist[] = {
        "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
        "winlogon.exe", "dwm.exe", "explorer.exe", "searchhost.exe",
        "startmenuexperiencehost.exe", "runtimebroker.exe", "taskhostw.exe",
        "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
        "antigravity", "devenv.exe", "msbuild.exe", "code.exe",
        nullptr
    };

    static bool IsProcessWhitelisted(const std::string& procName) {
        std::string lower = ToLower(procName);
        for (int i = 0; k_YaraWhitelist[i]; ++i) {
            if (lower == k_YaraWhitelist[i] || lower.find(k_YaraWhitelist[i]) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    // Hex string parser: turns "48 89 5C 24 ?? 57" into byte sequence + mask
    static bool ParseHexPattern(const std::string& hexStr, std::vector<BYTE>& outBytes, std::vector<bool>& outMask) {
        outBytes.clear();
        outMask.clear();

        std::istringstream iss(hexStr);
        std::string token;
        while (iss >> token) {
            if (token == "??" || token == "?") {
                outBytes.push_back(0x00);
                outMask.push_back(false); // wildcard
            } else if (token.length() >= 2 && isxdigit((unsigned char)token[0]) && isxdigit((unsigned char)token[1])) {
                BYTE b = (BYTE)std::strtoul(token.substr(0, 2).c_str(), nullptr, 16);
                outBytes.push_back(b);
                outMask.push_back(true);
            }
        }
        return !outBytes.empty();
    }

    // Boyer-Moore-Horspool search for plain ASCII (case-insensitive)
    static bool SearchAsciiNoCase(const BYTE* data, size_t size, const std::string& needle, uint64_t& matchOffset) {
        if (needle.empty() || size < needle.size()) return false;
        size_t nLen = needle.size();
        std::string lowerNeedle = ToLower(needle);

        // Simple optimized sliding window with early skip
        char firstChar = lowerNeedle[0];
        for (size_t i = 0; i <= size - nLen; ++i) {
            if (::tolower(data[i]) == firstChar) {
                bool match = true;
                for (size_t j = 1; j < nLen; ++j) {
                    if (::tolower(data[i + j]) != (unsigned char)lowerNeedle[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    matchOffset = i;
                    return true;
                }
            }
        }
        return false;
    }

    // Search for UTF-16LE wide string (e.g. 'a\0i\0m\0b\0o\0t\0')
    static bool SearchWideNoCase(const BYTE* data, size_t size, const std::string& needle, uint64_t& matchOffset) {
        if (needle.empty() || size < needle.size() * 2) return false;
        size_t nLen = needle.size();
        std::string lowerNeedle = ToLower(needle);

        char firstChar = lowerNeedle[0];
        for (size_t i = 0; i <= size - (nLen * 2); ++i) {
            if (::tolower(data[i]) == firstChar && data[i + 1] == 0) {
                bool match = true;
                for (size_t j = 1; j < nLen; ++j) {
                    size_t charIdx = i + (j * 2);
                    if (::tolower(data[charIdx]) != (unsigned char)lowerNeedle[j] || data[charIdx + 1] != 0) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    matchOffset = i;
                    return true;
                }
            }
        }
        return false;
    }

    // Masked hex byte search
    static bool SearchMaskedHex(const BYTE* data, size_t size, const std::vector<BYTE>& pat, const std::vector<bool>& mask, uint64_t& matchOffset) {
        if (pat.empty() || size < pat.size()) return false;
        size_t pLen = pat.size();

        for (size_t i = 0; i <= size - pLen; ++i) {
            bool match = true;
            for (size_t j = 0; j < pLen; ++j) {
                if (mask[j] && data[i + j] != pat[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                matchOffset = i;
                return true;
            }
        }
        return false;
    }

    // Add standard helper to create rules easily
    static void AddRuleHelper(const std::string& name,
                              const std::string& desc,
                              const std::string& sev,
                              ConditionMode cond,
                              int requiredMatches,
                              const std::vector<std::string>& tags,
                              const std::vector<std::pair<std::string, std::string>>& patterns)
    {
        YaraRule r;
        r.Name = name;
        r.Description = desc;
        r.Severity = sev;
        r.Condition = cond;
        r.RequiredMatches = requiredMatches;
        r.Tags = tags;

        for (const auto& p : patterns) {
            YaraPattern yp;
            yp.Identifier = p.first;
            if (!p.second.empty() && p.second[0] == '{') {
                // Hex pattern
                std::string hexContent = p.second;
                if (hexContent.length() >= 2) {
                    hexContent = hexContent.substr(1, hexContent.length() - 2);
                }
                yp.Type = MatchPatternType::HEX_BYTES;
                ParseHexPattern(hexContent, yp.ByteSequence, yp.ByteMask);
            } else {
                // Text pattern
                yp.Type = MatchPatternType::TEXT_ASCII;
                yp.TextValue = p.second;
                yp.NoCase = true;
            }
            r.Patterns.push_back(yp);
        }
        s_Rules.push_back(r);
    }

    // =========================================================================
    // Core Embedded YARA Ruleset (Tailored for Anti-Cheat, Bypasses & Malware)
    // =========================================================================
    static void RegisterBuiltinRules() {
        // 1. Aimbot & Combat Rules
        AddRuleHelper(
            "Game_Cheat_Aimbot_Core",
            "Detects high-confidence aimbot logic, silent aim hooks, and triggerbot keywords",
            "CRITICAL",
            ConditionMode::ANY_OF_THEM, 1,
            { "aimbot", "combat", "hack" },
            {
                { "$a1", "aimbot" },
                { "$a2", "silent_aim" },
                { "$a3", "silentaim" },
                { "$a4", "triggerbot" },
                { "$a5", "trigger_bot" },
                { "$a6", "fovcheat" },
                { "$a7", "aimassist_lock" },
                { "$a8", "real aimbot" },
                { "$a9", "real_aimbot" }
            }
        );

        // 2. Custom strings: Sniper Tracking, Collider Aimbot, Sope
        AddRuleHelper(
            "Game_Cheat_Collider_Sniper_Tracking",
            "Identifies sniper collider tracking, scoped aimbot algorithms, and custom collider injectors",
            "CRITICAL",
            ConditionMode::ANY_OF_THEM, 1,
            { "aimbot", "sniper", "collider", "tracking" },
            {
                { "$s1", "sniper tracking" },
                { "$s2", "sniper_tracking" },
                { "$s3", "sniper scoper tracking" },
                { "$s4", "sniper_scoper_tracking" },
                { "$s5", "scoper tracking" },
                { "$s6", "scoper_tracking" },
                { "$s7", "colloider aimbot" },
                { "$s8", "colloider_aimbot" },
                { "$s9", "collider aimbot" },
                { "$s10", "collider_aimbot" },
                { "$s11", "sniper sope" },
                { "$s12", "sniper_sope" },
                { "$s13", "sniper scope" }
            }
        );

        // 3. AI & Computer Vision Aimbot
        AddRuleHelper(
            "Game_Cheat_AI_Vision_Aimbot",
            "Detects AI/YOLO/OpenCV hardware and screen capture aimbots",
            "CRITICAL",
            ConditionMode::ANY_OF_THEM, 1,
            { "ai", "yolo", "computervision", "aimbot" },
            {
                { "$ai1", "ai aimbot" },
                { "$ai2", "ai_aimbot" },
                { "$ai3", "yolo_aimbot" },
                { "$ai4", "yoloaim" },
                { "$ai5", "opencv_aimbot" },
                { "$ai6", "onnxruntime_aimbot" },
                { "$ai7", "d3dshot" }
            }
        );

        // 4. Smooth & Brutal Rage Aimbot Rules
        AddRuleHelper(
            "Game_Cheat_Smooth_Brutal_Rage",
            "Detects smooth aimbot algorithms and brutal rage bot configurations",
            "CRITICAL",
            ConditionMode::ANY_OF_THEM, 1,
            { "rage", "smooth", "aimbot" },
            {
                { "$r1", "smooth aimbot brutal" },
                { "$r2", "smooth_aimbot_brutal" },
                { "$r3", "smooth aimbot" },
                { "$r4", "smooth_aimbot" },
                { "$r5", "brutal aimbot" },
                { "$r6", "brutal_aimbot" },
                { "$r7", "rage aimbot" },
                { "$r8", "rage_aimbot" },
                { "$r9", "ragebot" },
                { "$r10", "brutal_rage" }
            }
        );

        // 5. Hotkeys & Aim Trigger Keybinds
        AddRuleHelper(
            "Game_Cheat_Aimbot_Hotkeys",
            "Detects internal aimbot hotkey dispatchers and trigger key listeners",
            "HIGH",
            ConditionMode::ANY_OF_THEM, 1,
            { "hotkeys", "input", "aimkey" },
            {
                { "$hk1", "aimbot_hotkeys" },
                { "$hk2", "cheat_hotkeys" },
                { "$hk3", "trigger_hotkeys" },
                { "$hk4", "aimkey_press" },
                { "$hk5", "hotkeys_aim" }
            }
        );

        // 6. BSTKVMM Hypervisor Bypass
        AddRuleHelper(
            "Bypass_BSTKVMM_Hypervisor",
            "Detects BlueStacks VM hypervisor evasion module (bstkvmm.dll) and VM memory injection",
            "CRITICAL",
            ConditionMode::ANY_OF_THEM, 1,
            { "emulator", "bypass", "hypervisor", "bstkvmm" },
            {
                { "$b1", "bstkvmm.dll" },
                { "$b2", "bstkvmm" },
                { "$b3", "bstk_vmm" },
                { "$b4", "bstkvm" },
                { "$b5", "bstk_vmm.dll" },
                { "$b6", "\\\\.\\BstkDrv" },
                { "$b7", "\\\\.\\BstkVM" }
            }
        );

        // 7. Custom South-Asian & VIP Cheat Authors: Galib, Rabbi, Ahamed, Daku, Mirza, GTC, FIN
        AddRuleHelper(
            "Bypass_VIP_Authors_Signature",
            "Identifies private VIP cheat authors and custom loader signatures (Galib, Rabbi, Ahamed, Daku, Mirza, GTC, Fin)",
            "CRITICAL",
            ConditionMode::ANY_OF_THEM, 1,
            { "vip", "bypass", "galib", "rabbi", "daku", "mirza", "gtc" },
            {
                { "$v1", "galib" },
                { "$v2", "galib_vip" },
                { "$v3", "galib_bypass" },
                { "$v4", "rabbi" },
                { "$v5", "rabbi_vip" },
                { "$v6", "rabbi_bypass" },
                { "$v7", "ahamaed" },
                { "$v8", "ahamaed_vip" },
                { "$v9", "ahamed" },
                { "$v10", "ahamed_vip" },
                { "$v11", "daku" },
                { "$v12", "daku_vip" },
                { "$v13", "daku_bypass" },
                { "$v14", "mirza" },
                { "$v15", "mirza_vip" },
                { "$v16", "mirza_bypass" },
                { "$v17", "gtc_bypass" },
                { "$v18", "gtc_cheat" },
                { "$v19", "gtc_aimbot" },
                { "$v20", "gtc_vip" },
                { "$v21", "fin_real" },
                { "$v22", "fin_bypass" },
                { "$v23", "fin_injector" }
            }
        );

        // 8. Real BIOS & SMBIOS Hardware Spoofers
        AddRuleHelper(
            "Bypass_Real_Bios_Spoofer",
            "Detects motherboard BIOS modification, AMI flash bypass, and SMBIOS HWID spoofers",
            "CRITICAL",
            ConditionMode::ANY_OF_THEM, 1,
            { "spoofer", "hwid", "bios", "smbios" },
            {
                { "$bs1", "real bios" },
                { "$bs2", "real_bios" },
                { "$bs3", "bios_spoofer" },
                { "$bs4", "bios_serial" },
                { "$bs5", "bios_bypass" },
                { "$bs6", "bios_flash" },
                { "$bs7", "bios bypass" },
                { "$bs8", "AMIDEWIN" },
                { "$bs9", "DMIEdit" }
            }
        );

        // 9. KDMapper & Vulnerable Driver Loaders (BYOVD)
        AddRuleHelper(
            "Kernel_KDMapper_Vulnerable_Loader",
            "Identifies Bring-Your-Own-Vulnerable-Driver kernel exploits (KDMapper, KDU, Intel Nal)",
            "CRITICAL",
            ConditionMode::ANY_OF_THEM, 1,
            { "kernel", "kdmapper", "byovd", "driver" },
            {
                { "$k1", "kdmapper" },
                { "$k2", "iqvw64e.sys" },
                { "$k3", "\\Device\\Nal" },
                { "$k4", "\\Device\\GIO" },
                { "$k5", "kdu.exe" },
                { "$k6", "drv_loader" },
                { "$k7", "NtLoadDriver" }
            }
        );

        // 10. BlackBone & Manual Map Injectors
        AddRuleHelper(
            "Injector_BlackBone_ManualMap",
            "Detects BlackBone manual mapping framework strings and memory relocation routines",
            "CRITICAL",
            ConditionMode::ANY_OF_THEM, 1,
            { "injector", "blackbone", "manualmap" },
            {
                { "$m1", "BlackBone" },
                { "$m2", "ManualMap" },
                { "$m3", "ProcessMap" },
                { "$m4", "SetHook" },
                { "$m5", "DriverControl" }
            }
        );

        // 11. Process Hollowing & Injection Primitives
        AddRuleHelper(
            "Injector_Process_Hollowing_Primitives",
            "Identifies process replacement and unmapping API sequences used in hollowing",
            "CRITICAL",
            ConditionMode::AT_LEAST_N, 2,
            { "hollowing", "stealth", "injection" },
            {
                { "$h1", "NtUnmapViewOfSection" },
                { "$h2", "ZwUnmapViewOfSection" },
                { "$h3", "NtCreateSection" },
                { "$h4", "NtMapViewOfSection" },
                { "$h5", "NtSetInformationProcess" }
            }
        );

        // 12. DMA Hardware Cheats (PCILeech & Kmbox)
        AddRuleHelper(
            "Hardware_DMA_PCILeech_Kmbox",
            "Detects direct memory access FPGA firmware, PCILeech, and Kmbox network controllers",
            "CRITICAL",
            ConditionMode::ANY_OF_THEM, 1,
            { "dma", "pcileech", "kmbox", "fpga" },
            {
                { "$d1", "pcileech" },
                { "$d2", "kmboxNet" },
                { "$d3", "kmbox_net" },
                { "$d4", "kmboxB" },
                { "$d5", "leechcore" },
                { "$d6", "FPGA_DMA" }
            }
        );

        // 13. Cheat Engine & DBVM Hypervisor Hooks
        AddRuleHelper(
            "Tool_CheatEngine_DBVM",
            "Detects Cheat Engine memory debugger, DBVM dark byte virtual machine, and kernel drivers",
            "CRITICAL",
            ConditionMode::ANY_OF_THEM, 1,
            { "cheatengine", "dbvm", "debugger" },
            {
                { "$ce1", "Cheat Engine" },
                { "$ce2", "DBVM" },
                { "$ce3", "dbk64.sys" },
                { "$ce4", "CEDRIVER" },
                { "$ce5", "\\\\.\\CEDRIVER" }
            }
        );

        // 14. FiveM / GTA RedEngine & Script Cheats
        AddRuleHelper(
            "Game_FiveM_RedEngine_Exec",
            "Detects RedEngine Lua executor and FiveM memory bypass libraries",
            "CRITICAL",
            ConditionMode::ANY_OF_THEM, 1,
            { "fivem", "redengine", "lua", "executor" },
            {
                { "$fe1", "redengine" },
                { "$fe2", "red-engine" },
                { "$fe3", "redenginelib" },
                { "$fe4", "flkbypass" },
                { "$fe5", "headshot.dll" }
            }
        );

        // 15. Obfuscated PowerShell Downloader & Anti-Forensic wiper
        AddRuleHelper(
            "Forensics_PowerShell_Obfuscated_Wiper",
            "Detects PowerShell encoded downloaders, memory reflect, and eventlog clearing commands",
            "HIGH",
            ConditionMode::AT_LEAST_N, 2,
            { "powershell", "obfuscation", "wiper" },
            {
                { "$ps1", "FromBase64String" },
                { "$ps2", "DownloadString" },
                { "$ps3", "Invoke-Expression" },
                { "$ps4", "Clear-EventLog" },
                { "$ps5", "wevtutil cl" },
                { "$ps6", "Remove-ItemProperty" }
            }
        );

        // 16. Mimikatz & Credential Dumper in Memory
        AddRuleHelper(
            "Forensics_Mimikatz_Lsass_Dumper",
            "Detects LSASS credential harvesting and mimikatz sekurlsa modules",
            "CRITICAL",
            ConditionMode::AT_LEAST_N, 2,
            { "mimikatz", "lsass", "credential_theft" },
            {
                { "$mk1", "mimikatz" },
                { "$mk2", "sekurlsa" },
                { "$mk3", "logonpasswords" },
                { "$mk4", "wdigest" },
                { "$mk5", "lsadump" }
            }
        );
    }

    void Initialize() {
        std::lock_guard<std::mutex> lock(s_RulesMutex);
        if (s_Initialized) return;
        RegisterBuiltinRules();
        s_Initialized = true;
    }

    size_t GetLoadedRuleCount() {
        std::lock_guard<std::mutex> lock(s_RulesMutex);
        if (!s_Initialized) {
            RegisterBuiltinRules();
            s_Initialized = true;
        }
        return s_Rules.size();
    }

    // =========================================================================
    // Rule Parser: supports basic YARA grammar for .yar / .yara files
    // =========================================================================
    bool LoadRuleFromString(const std::string& ruleSource) {
        // Fast line-by-line YARA rule parser
        std::istringstream iss(ruleSource);
        std::string line;
        YaraRule currentRule;
        bool inRule = false;
        bool inStrings = false;
        bool inCondition = false;
        bool inMeta = false;

        while (std::getline(iss, line)) {
            // Trim leading/trailing whitespace
            size_t start = line.find_first_not_of(" \t\r\n");
            if (start == std::string::npos) continue;
            size_t end = line.find_last_not_of(" \t\r\n");
            line = line.substr(start, end - start + 1);

            if (line.rfind("//", 0) == 0 || line.rfind("/*", 0) == 0) continue;

            if (line.rfind("rule ", 0) == 0) {
                if (inRule && !currentRule.Name.empty()) {
                    std::lock_guard<std::mutex> lock(s_RulesMutex);
                    s_Rules.push_back(currentRule);
                }
                currentRule = YaraRule();
                inRule = true;
                inStrings = false;
                inCondition = false;
                inMeta = false;

                // Parse rule name
                std::istringstream lss(line);
                std::string kw, rName;
                lss >> kw >> rName;
                size_t colon = rName.find(':');
                if (colon != std::string::npos) rName = rName.substr(0, colon);
                currentRule.Name = rName;
                currentRule.Severity = "HIGH";
                currentRule.Description = "External YARA Rule: " + rName;
                continue;
            }

            if (!inRule) continue;

            if (line == "meta:") { inMeta = true; inStrings = false; inCondition = false; continue; }
            if (line == "strings:") { inStrings = true; inMeta = false; inCondition = false; continue; }
            if (line == "condition:") { inCondition = true; inMeta = false; inStrings = false; continue; }
            if (line == "}") {
                if (inRule && !currentRule.Name.empty()) {
                    std::lock_guard<std::mutex> lock(s_RulesMutex);
                    s_Rules.push_back(currentRule);
                }
                inRule = false;
                continue;
            }

            if (inStrings && line[0] == '$') {
                size_t eqPos = line.find('=');
                if (eqPos != std::string::npos) {
                    std::string id = line.substr(0, eqPos);
                    // trim id
                    size_t idEnd = id.find_last_not_of(" \t");
                    if (idEnd != std::string::npos) id = id.substr(0, idEnd + 1);

                    std::string val = line.substr(eqPos + 1);
                    size_t vStart = val.find_first_not_of(" \t");
                    if (vStart != std::string::npos) val = val.substr(vStart);

                    YaraPattern yp;
                    yp.Identifier = id;

                    if (!val.empty() && val[0] == '{') {
                        // Hex bytes
                        size_t closeBrace = val.find('}');
                        if (closeBrace != std::string::npos) {
                            std::string hexPart = val.substr(1, closeBrace - 1);
                            yp.Type = MatchPatternType::HEX_BYTES;
                            ParseHexPattern(hexPart, yp.ByteSequence, yp.ByteMask);
                        }
                    } else if (!val.empty() && val[0] == '"') {
                        size_t secondQuote = val.find('"', 1);
                        if (secondQuote != std::string::npos) {
                            std::string strVal = val.substr(1, secondQuote - 1);
                            std::string modifiers = val.substr(secondQuote + 1);
                            yp.Type = MatchPatternType::TEXT_ASCII;
                            yp.TextValue = strVal;
                            yp.NoCase = (modifiers.find("nocase") != std::string::npos);
                            yp.Wide = (modifiers.find("wide") != std::string::npos);
                            yp.Ascii = (modifiers.find("ascii") != std::string::npos || !yp.Wide);
                        }
                    }

                    if (!yp.TextValue.empty() || !yp.ByteSequence.empty()) {
                        currentRule.Patterns.push_back(yp);
                    }
                }
            }

            if (inCondition) {
                std::string condLower = ToLower(line);
                if (condLower.find("all of them") != std::string::npos) {
                    currentRule.Condition = ConditionMode::ALL_OF_THEM;
                } else if (condLower.find("any of them") != std::string::npos) {
                    currentRule.Condition = ConditionMode::ANY_OF_THEM;
                } else if (condLower.find(" of them") != std::string::npos) {
                    currentRule.Condition = ConditionMode::AT_LEAST_N;
                    currentRule.RequiredMatches = 2; // sensible default
                }
            }
        }

        if (inRule && !currentRule.Name.empty()) {
            std::lock_guard<std::mutex> lock(s_RulesMutex);
            s_Rules.push_back(currentRule);
        }
        return true;
    }

    size_t LoadRulesFromFile(const std::string& filePath) {
        std::ifstream file(filePath);
        if (!file.is_open()) return 0;
        std::stringstream buffer;
        buffer << file.rdbuf();
        size_t before = s_Rules.size();
        LoadRuleFromString(buffer.str());
        return s_Rules.size() - before;
    }

    size_t LoadRulesFromDirectory(const std::string& directoryPath) {
        size_t loaded = 0;
        try {
            if (!std::filesystem::exists(directoryPath)) return 0;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(directoryPath)) {
                if (entry.is_regular_file()) {
                    auto ext = entry.path().extension().string();
                    if (ext == ".yar" || ext == ".yara") {
                        loaded += LoadRulesFromFile(entry.path().string());
                    }
                }
            }
        } catch (...) {}
        return loaded;
    }

    // =========================================================================
    // Scanning Engine
    // =========================================================================
    std::vector<YaraDetection> ScanBuffer(const BYTE* data, size_t size, 
                                         const std::string& targetLabel, 
                                         TargetType type, 
                                         DWORD pid, 
                                         uint64_t baseAddr)
    {
        Initialize();
        std::vector<YaraDetection> detections;
        if (!data || size < 4) return detections;

        std::lock_guard<std::mutex> lock(s_RulesMutex);

        for (const auto& rule : s_Rules) {
            std::vector<std::string> matchedIds;
            uint64_t firstHitOffset = 0;

            for (const auto& pat : rule.Patterns) {
                uint64_t offset = 0;
                bool hit = false;

                if (pat.Type == MatchPatternType::HEX_BYTES) {
                    hit = SearchMaskedHex(data, size, pat.ByteSequence, pat.ByteMask, offset);
                } else {
                    if (pat.Wide) {
                        hit = SearchWideNoCase(data, size, pat.TextValue, offset);
                    }
                    if (!hit && pat.Ascii) {
                        hit = SearchAsciiNoCase(data, size, pat.TextValue, offset);
                    }
                }

                if (hit) {
                    matchedIds.push_back(pat.Identifier + (!pat.TextValue.empty() ? (" (" + pat.TextValue + ")") : ""));
                    if (matchedIds.size() == 1) firstHitOffset = offset;
                }
            }

            bool ruleTriggered = false;
            switch (rule.Condition) {
                case ConditionMode::ANY_OF_THEM:
                    ruleTriggered = (!matchedIds.empty());
                    break;
                case ConditionMode::ALL_OF_THEM:
                    ruleTriggered = (matchedIds.size() == rule.Patterns.size() && !rule.Patterns.empty());
                    break;
                case ConditionMode::AT_LEAST_N:
                    ruleTriggered = ((int)matchedIds.size() >= rule.RequiredMatches);
                    break;
                default:
                    ruleTriggered = (!matchedIds.empty());
                    break;
            }

            if (ruleTriggered) {
                YaraDetection det;
                det.RuleName = rule.Name;
                det.Severity = rule.Severity;
                det.Description = rule.Description;
                det.Tags = rule.Tags;
                det.MatchedPatterns = matchedIds;
                det.Type = type;
                det.TargetIdentifier = targetLabel;
                det.ProcessId = pid;
                det.MemoryAddressOrOffset = baseAddr + firstHitOffset;
                det.Confidence = (matchedIds.size() >= 2) ? 0.99f : 0.90f;
                detections.push_back(det);
            }
        }

        return detections;
    }

    std::vector<YaraDetection> ScanFile(const std::string& filePath) {
        std::vector<YaraDetection> results;
        try {
            std::ifstream file(filePath, std::ios::binary | std::ios::ate);
            if (!file.is_open()) return results;
            std::streamsize sz = file.tellg();
            if (sz <= 0 || sz > 150 * 1024 * 1024) return results; // skip > 150MB files

            file.seekg(0, std::ios::beg);
            std::vector<BYTE> buffer((size_t)sz);
            if (file.read((char*)buffer.data(), sz)) {
                results = ScanBuffer(buffer.data(), buffer.size(), filePath, TargetType::FILE_DISK, 0, 0);
            }
        } catch (...) {}
        return results;
    }

    std::vector<YaraDetection> ScanProcessMemory(DWORD pid, const std::string& processName) {
        std::vector<YaraDetection> results;
        if (IsProcessWhitelisted(processName)) return results;

        HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) return results;

        MEMORY_BASIC_INFORMATION mbi = {};
        ULONG_PTR addr = 0x10000;
        const SIZE_T kMaxRegionScan = 4 * 1024 * 1024; // 4MB per region limit

        while (VirtualQueryEx(hProc, (PVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect == PAGE_READWRITE || 
                 mbi.Protect == PAGE_EXECUTE_READWRITE || 
                 mbi.Protect == PAGE_EXECUTE_READ)) 
            {
                SIZE_T toRead = (std::min)(mbi.RegionSize, kMaxRegionScan);
                std::vector<BYTE> buffer(toRead);
                SIZE_T bytesRead = 0;

                NTSTATUS status = SyscallEngine::DirectNtReadVirtualMemory(
                    hProc, mbi.BaseAddress, buffer.data(), toRead, &bytesRead);

                if (NT_SUCCESS(status) && bytesRead > 16) {
                    std::string label = processName + " (PID: " + std::to_string(pid) + ")";
                    auto hits = ScanBuffer(buffer.data(), bytesRead, label, TargetType::PROCESS_MEMORY, pid, (uint64_t)mbi.BaseAddress);
                    results.insert(results.end(), hits.begin(), hits.end());
                    if (results.size() > 25) break; // prevent flood from single process
                }
            }

            addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            if (addr >= 0x7FFFFFFF0000ULL || mbi.RegionSize == 0) break;
        }

        CloseHandle(hProc);
        return results;
    }

    std::vector<YaraDetection> ScanAllProcesses() {
        std::vector<YaraDetection> allResults;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return allResults;

        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID <= 4) continue;
                char narrowName[MAX_PATH] = {};
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrowName, MAX_PATH, NULL, NULL);

                if (!IsProcessWhitelisted(narrowName)) {
                    auto res = ScanProcessMemory(pe.th32ProcessID, narrowName);
                    allResults.insert(allResults.end(), res.begin(), res.end());
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
        return allResults;
    }

    std::vector<YaraDetection> ScanDropLocations() {
        std::vector<YaraDetection> results;
        std::vector<std::string> pathsToScan;

        // Temp
        char tempPath[MAX_PATH] = {};
        if (GetTempPathA(MAX_PATH, tempPath) > 0) pathsToScan.push_back(tempPath);

        // Downloads & Desktop
        PWSTR downloadsPath = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &downloadsPath))) {
            char p[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, downloadsPath, -1, p, MAX_PATH, NULL, NULL);
            pathsToScan.push_back(p);
            CoTaskMemFree(downloadsPath);
        }

        PWSTR desktopPath = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, NULL, &desktopPath))) {
            char p[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, desktopPath, -1, p, MAX_PATH, NULL, NULL);
            pathsToScan.push_back(p);
            CoTaskMemFree(desktopPath);
        }

        for (const auto& dir : pathsToScan) {
            try {
                if (!std::filesystem::exists(dir)) continue;
                int count = 0;
                for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                    if (count++ > 60) break; // sample top 60 files in each folder
                    if (entry.is_regular_file()) {
                        auto ext = entry.path().extension().string();
                        std::string lowerExt = ToLower(ext);
                        if (lowerExt == ".exe" || lowerExt == ".dll" || lowerExt == ".sys" || lowerExt == ".bat" || lowerExt == ".vbs") {
                            auto hits = ScanFile(entry.path().string());
                            results.insert(results.end(), hits.begin(), hits.end());
                        }
                    }
                }
            } catch (...) {}
        }

        return results;
    }

    std::vector<YaraDetection> RunCompleteYaraSweep(DWORD targetPid, const std::string& targetName) {
        Initialize();

        // Check if there is a local `yara_rules` folder in the current directory or workspace
        LoadRulesFromDirectory("yara_rules");
        LoadRulesFromDirectory("rules");

        std::vector<YaraDetection> allDetections;

        // 1. Process Memory Scan
        if (targetPid > 0) {
            auto procHits = ScanProcessMemory(targetPid, targetName.empty() ? "TargetProcess" : targetName);
            allDetections.insert(allDetections.end(), procHits.begin(), procHits.end());
        } else {
            auto procHits = ScanAllProcesses();
            allDetections.insert(allDetections.end(), procHits.begin(), procHits.end());
        }

        // 2. High-Risk Drop Locations Scan
        auto dropHits = ScanDropLocations();
        allDetections.insert(allDetections.end(), dropHits.begin(), dropHits.end());

        return allDetections;
    }

} // namespace YaraScanner
