#pragma once
#include <windows.h>
#include <d3d11.h>
#include <string>
#include <vector>
#include <functional>
#include "ReportGenerator.hpp"

namespace ImGuiDashboard {

    // Progress update callback: (progress 0.0-1.0, currentStep, currentSubtext, liveItem)
    using ProgressCallback = std::function<void(float progress, const std::string& currentStep, const std::string& currentSubtext, const std::string& liveItem)>;

    // Function type to perform scan iterations asynchronously with progress feedback
    using ScanCallback = std::function<ReportGenerator::ScanReportData(DWORD targetPid, const std::string& targetName, ProgressCallback onProgress)>;

    // Push live scan log item into ImGui buffer
    void PushLiveScanLog(const std::string& logLine);

    // Run the native DirectX 11 + Dear ImGui desktop application
    int Run(HINSTANCE hInstance, int nCmdShow, ScanCallback scanFunc, DWORD initialPid = 0, const std::string& initialTargetName = "");

}
