#include "NetworkAuditor.hpp"
#include <iphlpapi.h>
#include <psapi.h>
#include <shlwapi.h>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

#ifndef TCP_TABLE_OWNER_PID_ALL
#define TCP_TABLE_OWNER_PID_ALL 5
#endif

#ifndef MIB_TCP_STATE_CLOSED
#define MIB_TCP_STATE_CLOSED 1
#define MIB_TCP_STATE_LISTEN 2
#define MIB_TCP_STATE_SYN_SENT 3
#define MIB_TCP_STATE_SYN_RCVD 4
#define MIB_TCP_STATE_ESTAB 5
#define MIB_TCP_STATE_FIN_WAIT1 6
#define MIB_TCP_STATE_FIN_WAIT2 7
#define MIB_TCP_STATE_CLOSE_WAIT 8
#define MIB_TCP_STATE_CLOSING 9
#define MIB_TCP_STATE_LAST_ACK 10
#define MIB_TCP_STATE_TIME_WAIT 11
#define MIB_TCP_STATE_DELETE_TCB 12
#endif

typedef DWORD(WINAPI* pfnGetExtendedTcpTable)(
    PVOID pTcpTable,
    PDWORD pdwSize,
    BOOL bOrder,
    ULONG ulAf,
    ULONG TableClass,
    ULONG Reserved
);

namespace NetworkAuditor {

    static std::string IpToString(DWORD ip) {
        char buf[32] = { 0 };
        sprintf_s(buf, "%u.%u.%u.%u", (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF));
        return std::string(buf);
    }

    static std::string TcpStateToString(DWORD state) {
        switch (state) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default: return "STATE_" + std::to_string(state);
        }
    }

    static std::string GetProcessName(DWORD pid) {
        if (pid == 0) return "Idle";
        if (pid == 4) return "System";

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return "PID_" + std::to_string(pid);

        WCHAR szPath[MAX_PATH] = { 0 };
        DWORD dwSz = MAX_PATH;
        QueryFullProcessImageNameW(h, 0, szPath, &dwSz);
        CloseHandle(h);

        WCHAR* pFile = PathFindFileNameW(szPath);
        char buf[MAX_PATH] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, pFile, -1, buf, MAX_PATH, NULL, NULL);
        return (strlen(buf) > 0) ? std::string(buf) : "PID_" + std::to_string(pid);
    }

    std::vector<NetworkConnection> AuditNetworkConnections(DWORD targetPid) {
        std::vector<NetworkConnection> connections;

        HMODULE hIphlp = LoadLibraryW(L"iphlpapi.dll");
        if (!hIphlp) return connections;

        auto pGetExtendedTcpTable = (pfnGetExtendedTcpTable)GetProcAddress(hIphlp, "GetExtendedTcpTable");
        if (!pGetExtendedTcpTable) {
            FreeLibrary(hIphlp);
            return connections;
        }

        DWORD dwSize = 0;
        pGetExtendedTcpTable(NULL, &dwSize, FALSE, 2 /* AF_INET */, TCP_TABLE_OWNER_PID_ALL, 0);
        if (dwSize > 0) {
            std::vector<BYTE> buffer(dwSize);
            if (pGetExtendedTcpTable(buffer.data(), &dwSize, FALSE, 2 /* AF_INET */, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                auto* pTable = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
                for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
                    const auto& row = pTable->table[i];
                    if (targetPid != 0 && row.dwOwningPid != targetPid) continue;

                    NetworkConnection c;
                    c.ProcessId = row.dwOwningPid;
                    c.ProcessName = GetProcessName(row.dwOwningPid);
                    c.Protocol = "TCP";
                    c.LocalAddress = IpToString(row.dwLocalAddr);
                    c.RemoteAddress = IpToString(row.dwRemoteAddr);
                    c.LocalPort = (((row.dwLocalPort & 0xFF) << 8) | ((row.dwLocalPort >> 8) & 0xFF));
                    c.RemotePort = (((row.dwRemotePort & 0xFF) << 8) | ((row.dwRemotePort >> 8) & 0xFF));
                    c.State = TcpStateToString(row.dwState);

                    std::string lowerProc = c.ProcessName;
                    std::transform(lowerProc.begin(), lowerProc.end(), lowerProc.begin(), ::tolower);

                    // Flag established connections from non-system / untrusted processes
                    if (c.State == "ESTABLISHED" && c.RemoteAddress != "127.0.0.1" && c.RemoteAddress != "0.0.0.0") {
                        if (lowerProc.find("cheat") != std::string::npos || lowerProc.find("hack") != std::string::npos ||
                            lowerProc.find("inject") != std::string::npos || lowerProc.find("cruz") != std::string::npos ||
                            lowerProc.find("renault") != std::string::npos || lowerProc.find("finalexp") != std::string::npos) {
                            
                            c.Severity = "CRITICAL";
                            c.Description = "Active C2 / Authentication connection to " + c.RemoteAddress + ":" + std::to_string(c.RemotePort) + " from cheat binary '" + c.ProcessName + "'.";
                            connections.push_back(c);
                        }
                        else if (targetPid != 0 && row.dwOwningPid == targetPid) {
                            c.Severity = "INFO";
                            c.Description = "Target game connection to " + c.RemoteAddress + ":" + std::to_string(c.RemotePort);
                            connections.push_back(c);
                        }
                    }
                }
            }
        }

        FreeLibrary(hIphlp);
        return connections;
    }
}
