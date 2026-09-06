#include "ProcessTreeAnalyzer.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <iostream>
#include <algorithm>
#include <map>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

namespace ProcessTreeAnalyzer {

    static std::string ToLower(const std::string& str) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower;
    }

    std::vector<ProcessTreeDetection> AnalyzeProcessTrees() {
        std::vector<ProcessTreeDetection> detections;

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return detections;

        std::map<DWORD, std::string> pidToName;
        std::map<DWORD, DWORD> pidToParent;

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnap, &pe)) {
            do {
                char buf[MAX_PATH] = { 0 };
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, buf, MAX_PATH, NULL, NULL);
                pidToName[pe.th32ProcessID] = buf;
                pidToParent[pe.th32ProcessID] = pe.th32ParentProcessID;
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);

        for (const auto& kv : pidToParent) {
            DWORD pid = kv.first;
            DWORD ppid = kv.second;
            std::string procName = pidToName[pid];
            std::string procLower = ToLower(procName);

            std::string parentName = (pidToName.find(ppid) != pidToName.end()) ? pidToName[ppid] : "[Dead / Terminated Parent PID " + std::to_string(ppid) + "]";
            std::string parentLower = ToLower(parentName);

            // Case A: Suspicious loader parent launching system binaries or game injectors
            if (parentLower.find("loader") != std::string::npos || parentLower.find("inject") != std::string::npos ||
                parentLower.find("cruz") != std::string::npos || parentLower.find("cheat") != std::string::npos) {
                
                ProcessTreeDetection d;
                d.ProcessId = pid;
                d.ParentProcessId = ppid;
                d.ProcessName = procName;
                d.ParentProcessName = parentName;
                d.DetectionType = "SUSPICIOUS_LOADER_PARENT";
                d.Severity = "CRITICAL";
                d.Description = "Process '" + procName + "' (PID " + std::to_string(pid) + ") was spawned by suspicious cheat loader parent '" + parentName + "'.";
                detections.push_back(d);
            }

            // Case B: Cheat binary orphaned (parent terminated immediately to evade detection)
            if ((procLower.find("cheat") != std::string::npos || procLower.find("hack") != std::string::npos ||
                 procLower.find("inject") != std::string::npos || procLower.find("bypass") != std::string::npos ||
                 procLower.find("finalexp") != std::string::npos) && pidToName.find(ppid) == pidToName.end()) {
                
                ProcessTreeDetection d;
                d.ProcessId = pid;
                d.ParentProcessId = ppid;
                d.ProcessName = procName;
                d.ParentProcessName = parentName;
                d.DetectionType = "HIDDEN_ORPHAN_PROCESS";
                d.Severity = "CRITICAL";
                d.Description = "Suspicious cheat binary '" + procName + "' running orphaned (parent loader PID " + std::to_string(ppid) + " terminated after injection).";
                detections.push_back(d);
            }
        }

        return detections;
    }
}
