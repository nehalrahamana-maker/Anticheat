#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace EmulatorScanner {

    struct EmulatorInstance {
        DWORD ProcessId = 0;
        std::string ProcessName;
        std::string MainWindowTitle;
        HWND MainWindowHandle = NULL;
        bool IsRunning = false;
        std::vector<std::string> LoadedModules;
    };

    struct EmulatorDetection {
        DWORD ProcessId = 0;
        std::string ProcessName;
        std::string DetectionType;
        std::string Severity; // CRITICAL, HIGH, MEDIUM
        std::string TargetObject;
        std::string Description;
    };

    // Auto-discover any running instance of HD-Player.exe, BlueStacks, or MSI App Player
    std::vector<EmulatorInstance> FindRunningEmulators();

    // Deep integrity scan specifically for HD-Player.exe
    std::vector<EmulatorDetection> ScanEmulatorIntegrity(DWORD pid, const std::string& procName);
}
