#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace OverlayAuditor {

    struct OverlayDetection {
        DWORD ProcessId = 0;
        std::string ProcessName;
        HWND WindowHandle = NULL;
        std::string WindowTitle;
        std::string WindowClass;
        std::string DetectionType; // TRANSPARENT_ESP_OVERLAY, NVIDIA_OVERLAY_HIJACK, TOPMOST_CLOAKED_WINDOW
        std::string Severity;      // CRITICAL, HIGH
        std::string Description;
    };

    // Scans the desktop for rogue transparent ESP overlays positioned over the game/emulator
    std::vector<OverlayDetection> ScanOverlayWindows(DWORD targetPid);
}
