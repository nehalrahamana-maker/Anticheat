#include "ScreenshotCapture.hpp"
#include <iostream>
#include <fstream>
#include <vector>

namespace ScreenshotCapture {

    static bool SaveBitmapToFile(HBITMAP hBitmap, HDC hDC, int width, int height, const std::string& filePath) {
        BITMAPINFO bi = { 0 };
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = width;
        bi.bmiHeader.biHeight = height;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 24;
        bi.bmiHeader.biCompression = BI_RGB;

        DWORD dwBmpSize = ((width * 24 + 31) / 32) * 4 * height;
        std::vector<BYTE> lpPixels(dwBmpSize);

        if (!GetDIBits(hDC, hBitmap, 0, height, lpPixels.data(), &bi, DIB_RGB_COLORS)) {
            return false;
        }

        BITMAPFILEHEADER bfh = { 0 };
        bfh.bfType = 0x4D42; // 'BM'
        bfh.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwBmpSize;
        bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

        std::ofstream out(filePath, std::ios::binary);
        if (!out.is_open()) return false;

        out.write(reinterpret_cast<char*>(&bfh), sizeof(bfh));
        out.write(reinterpret_cast<char*>(&bi.bmiHeader), sizeof(bi.bmiHeader));
        out.write(reinterpret_cast<char*>(lpPixels.data()), dwBmpSize);
        out.close();

        return true;
    }

    ScreenshotResult CaptureWindowScreenshot(HWND hwnd, const std::string& outputFileName) {
        ScreenshotResult res;
        if (!hwnd || !IsWindow(hwnd)) {
            res.ErrorMessage = "Invalid window handle.";
            return res;
        }

        RECT rc;
        GetWindowRect(hwnd, &rc);
        int w = rc.right - rc.left;
        int h = rc.bottom - rc.top;

        if (w <= 0 || h <= 0) {
            res.ErrorMessage = "Window dimensions are zero.";
            return res;
        }

        HDC hdcScreen = GetDC(NULL);
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, w, h);
        HGDIOBJ hOld = SelectObject(hdcMem, hBitmap);

        // Try PrintWindow first (works even if occluded), fallback to BitBlt
        if (!PrintWindow(hwnd, hdcMem, 2)) {
            BitBlt(hdcMem, 0, 0, w, h, hdcScreen, rc.left, rc.top, SRCCOPY);
        }

        if (SaveBitmapToFile(hBitmap, hdcMem, w, h, outputFileName)) {
            res.Success = true;
            res.SavedFilePath = outputFileName;
            res.Width = w;
            res.Height = h;
        }
        else {
            res.ErrorMessage = "Failed to write bitmap to disk.";
        }

        SelectObject(hdcMem, hOld);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);

        return res;
    }

    ScreenshotResult CaptureDesktopScreenshot(const std::string& outputFileName) {
        ScreenshotResult res;
        int w = GetSystemMetrics(SM_CXSCREEN);
        int h = GetSystemMetrics(SM_CYSCREEN);

        HDC hdcScreen = GetDC(NULL);
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, w, h);
        HGDIOBJ hOld = SelectObject(hdcMem, hBitmap);

        BitBlt(hdcMem, 0, 0, w, h, hdcScreen, 0, 0, SRCCOPY);

        if (SaveBitmapToFile(hBitmap, hdcMem, w, h, outputFileName)) {
            res.Success = true;
            res.SavedFilePath = outputFileName;
            res.Width = w;
            res.Height = h;
        }
        else {
            res.ErrorMessage = "Failed to write desktop bitmap to disk.";
        }

        SelectObject(hdcMem, hOld);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);

        return res;
    }
}
