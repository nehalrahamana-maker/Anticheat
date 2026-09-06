#pragma once
#include <windows.h>
#include <string>

namespace ScreenshotCapture {

    struct ScreenshotResult {
        bool Success = false;
        std::string SavedFilePath;
        int Width = 0;
        int Height = 0;
        std::string ErrorMessage;
    };

    // Captures visual screenshot of a window or desktop bounds as forensic evidence
    ScreenshotResult CaptureWindowScreenshot(HWND hwnd, const std::string& outputFileName);

    // Captures entire primary display desktop
    ScreenshotResult CaptureDesktopScreenshot(const std::string& outputFileName);
}
