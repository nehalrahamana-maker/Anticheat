#include "OverlayAuditor.hpp"
#include <psapi.h>
#include <shlwapi.h>
#include <algorithm>
#include <iostream>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

namespace OverlayAuditor {

    static std::string ToLower(const std::string& str) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower;
    }

    std::vector<OverlayDetection> ScanOverlayWindows(DWORD targetPid) {
        std::vector<OverlayDetection> detections;

        RECT targetRect = { 0 };
        bool hasTargetRect = false;

        // 1. Locate target game/emulator window rect
        if (targetPid != 0) {
            struct TargetCtx {
                DWORD pid;
                RECT  rect;
                bool  found;
            };
            TargetCtx ctx = { targetPid, { 0 }, false };

            EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                auto* p = reinterpret_cast<TargetCtx*>(lParam);
                DWORD wndPid = 0;
                GetWindowThreadProcessId(hwnd, &wndPid);
                if (wndPid == p->pid && IsWindowVisible(hwnd)) {
                    GetWindowRect(hwnd, &p->rect);
                    if ((p->rect.right - p->rect.left) > 200 && (p->rect.bottom - p->rect.top) > 200) {
                        p->found = true;
                        return FALSE;
                    }
                }
                return TRUE;
            }, (LPARAM)&ctx);

            hasTargetRect = ctx.found;
            targetRect = ctx.rect;
        }

        // 2. Enumerate all windows looking for transparent click-through topmost ESP overlays
        struct ScanCtx {
            DWORD targetPid;
            RECT  targetRect;
            bool  hasTargetRect;
            std::vector<OverlayDetection>* pDetections;
        };

        ScanCtx sCtx = { targetPid, targetRect, hasTargetRect, &detections };

        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto* p = reinterpret_cast<ScanCtx*>(lParam);
            if (!IsWindowVisible(hwnd)) return TRUE;

            DWORD wndPid = 0;
            GetWindowThreadProcessId(hwnd, &wndPid);
            if (wndPid == 0 || wndPid == 4 || wndPid == p->targetPid || wndPid == GetCurrentProcessId()) return TRUE;

            LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
            bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
            bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
            bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;

            if (isLayered && isTransparent) {
                // Get process name of overlay window owner
                HANDLE hOwner = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, wndPid);
                std::string procName = "PID_" + std::to_string(wndPid);
                if (hOwner) {
                    WCHAR szPath[MAX_PATH] = { 0 };
                    DWORD dwSz = MAX_PATH;
                    QueryFullProcessImageNameW(hOwner, 0, szPath, &dwSz);
                    CloseHandle(hOwner);

                    WCHAR* pFile = PathFindFileNameW(szPath);
                    char nameBuf[MAX_PATH] = { 0 };
                    WideCharToMultiByte(CP_UTF8, 0, pFile, -1, nameBuf, MAX_PATH, NULL, NULL);
                    if (strlen(nameBuf) > 0) procName = nameBuf;
                }

                char titleBuf[256] = { 0 };
                GetWindowTextA(hwnd, titleBuf, sizeof(titleBuf));

                char classBuf[256] = { 0 };
                GetClassNameA(hwnd, classBuf, sizeof(classBuf));

                std::string lowerProc = ToLower(procName);
                std::string lowerClass = ToLower(classBuf);

                // Filter out legitimate OS overlays
                if (lowerProc != "explorer.exe" && lowerProc != "dwm.exe" && lowerProc != "shellexperiencehost.exe" &&
                    lowerProc != "searchapp.exe" && lowerProc != "startmenuexperiencehost.exe" &&
                    lowerClass.find("tooltip") == std::string::npos) {
                    
                    OverlayDetection d;
                    d.ProcessId = wndPid;
                    d.ProcessName = procName;
                    d.WindowHandle = hwnd;
                    d.WindowTitle = titleBuf;
                    d.WindowClass = classBuf;
                    d.Severity = "CRITICAL";

                    if (lowerClass.find("nvidia") != std::string::npos || lowerProc.find("nv") != std::string::npos) {
                        d.DetectionType = "NVIDIA_OVERLAY_HIJACK (nvidia_guna.cpp)";
                        d.Description = "NVIDIA GeForce ShadowPlay overlay window hijacked with WS_EX_TRANSPARENT | WS_EX_LAYERED for undetected ESP rendering.";
                    }
                    else {
                        d.DetectionType = "TRANSPARENT_ESP_OVERLAY";
                        d.Description = "External click-through transparent layered overlay window (" + std::string(classBuf) + ") active from '" + procName + "'. Typical external ESP/Aimbot overlay.";
                    }

                    p->pDetections->push_back(d);
                }
            }

            return TRUE;
        }, (LPARAM)&sCtx);

        return detections;
    }
}
