#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace NetworkAuditor {

    struct NetworkConnection {
        DWORD ProcessId = 0;
        std::string ProcessName;
        std::string Protocol;      // TCP, UDP
        std::string LocalAddress;
        std::string RemoteAddress;
        DWORD LocalPort = 0;
        DWORD RemotePort = 0;
        std::string State;
        std::string Severity;      // CRITICAL, HIGH, INFO
        std::string Description;
    };

    // Audits active TCP/UDP network connections across the system
    std::vector<NetworkConnection> AuditNetworkConnections(DWORD targetPid = 0);
}
