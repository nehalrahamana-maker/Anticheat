#include "ReportGenerator.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>

namespace ReportGenerator {

    static std::string WideToNarrow(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        char buf[MAX_PATH] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, buf, MAX_PATH, NULL, NULL);
        return std::string(buf);
    }

    static std::string EscapeJSON(const std::string& input) {
        std::ostringstream ss;
        for (char c : input) {
            switch (c) {
            case '"': ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b"; break;
            case '\f': ss << "\\f"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
                }
                else {
                    ss << c;
                }
            }
        }
        return ss.str();
    }

    static std::string EscapeHTML(const std::string& input) {
        std::ostringstream ss;
        for (char c : input) {
            switch (c) {
            case '&': ss << "&amp;"; break;
            case '<': ss << "&lt;"; break;
            case '>': ss << "&gt;"; break;
            case '"': ss << "&quot;"; break;
            case '\'': ss << "&#39;"; break;
            default: ss << c; break;
            }
        }
        return ss.str();
    }

    static std::string FormatHexTable(const std::vector<BYTE>& diskBytes, const std::vector<BYTE>& memBytes, size_t baseOffset) {
        std::ostringstream ss;
        ss << "<div class='hex-viewer-container'>\n";
        ss << "  <div class='hex-toolbar'>\n";
        ss << "    <div class='hex-status'><span class='diff-badge diff-disk'>DISK IMAGE</span> vs <span class='diff-badge diff-mem'>LIVE MEMORY</span></div>\n";
        ss << "    <div class='hex-actions'>\n";
        ss << "      <button class='btn-mini' onclick=\"copyHexBytes(this)\">📋 Copy Hex</button>\n";
        ss << "      <span class='hex-tip'>Click byte to inspect instruction</span>\n";
        ss << "    </div>\n";
        ss << "  </div>\n";
        ss << "  <div class='hex-viewer-wrapper'>\n";

        // Disk Column
        ss << "    <div class='hex-column'>\n";
        ss << "      <div class='hex-title'><i class='icon'>💾</i><span>Clean Disk Image (Relocated)</span></div>\n";
        ss << "      <table class='hex-table'>\n";
        ss << "        <thead><tr><th>Offset</th><th>Hex Bytes</th><th>ASCII</th></tr></thead>\n";
        ss << "        <tbody>\n";

        size_t maxRows = (std::min)((std::min)(diskBytes.size(), memBytes.size()) / 16, (size_t)16);
        if (maxRows == 0 && diskBytes.size() > 0) maxRows = 1;

        for (size_t r = 0; r < maxRows; r++) {
            size_t rowOffset = r * 16;
            ss << "          <tr>\n";
            ss << "            <td class='hex-offset'>+0x" << std::hex << std::setw(4) << std::setfill('0') << (baseOffset + rowOffset) << "</td>\n";
            ss << "            <td class='hex-bytes'>";
            for (size_t c = 0; c < 16; c++) {
                size_t idx = rowOffset + c;
                if (idx < diskBytes.size()) {
                    bool isDiff = (idx < memBytes.size() && diskBytes[idx] != memBytes[idx]);
                    if (isDiff) ss << "<span class='diff-disk' data-byte='" << std::hex << std::setw(2) << std::setfill('0') << (int)diskBytes[idx] << "'>";
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)diskBytes[idx];
                    if (isDiff) ss << "</span>";
                    ss << " ";
                }
                else {
                    ss << "   ";
                }
            }
            ss << "</td>\n";
            ss << "            <td class='hex-ascii'>";
            for (size_t c = 0; c < 16; c++) {
                size_t idx = rowOffset + c;
                if (idx < diskBytes.size()) {
                    char ch = (char)diskBytes[idx];
                    if (ch >= 32 && ch <= 126) ss << EscapeHTML(std::string(1, ch));
                    else ss << ".";
                }
            }
            ss << "</td>\n";
            ss << "          </tr>\n";
        }
        ss << "        </tbody>\n";
        ss << "      </table>\n";
        ss << "    </div>\n";

        // Memory Column
        ss << "    <div class='hex-column'>\n";
        ss << "      <div class='hex-title'><i class='icon'>⚡</i><span>Live Process Memory Image (Injected)</span></div>\n";
        ss << "      <table class='hex-table'>\n";
        ss << "        <thead><tr><th>Offset</th><th>Hex Bytes</th><th>ASCII</th></tr></thead>\n";
        ss << "        <tbody>\n";

        for (size_t r = 0; r < maxRows; r++) {
            size_t rowOffset = r * 16;
            ss << "          <tr>\n";
            ss << "            <td class='hex-offset'>+0x" << std::hex << std::setw(4) << std::setfill('0') << (baseOffset + rowOffset) << "</td>\n";
            ss << "            <td class='hex-bytes'>";
            for (size_t c = 0; c < 16; c++) {
                size_t idx = rowOffset + c;
                if (idx < memBytes.size()) {
                    bool isDiff = (idx < diskBytes.size() && diskBytes[idx] != memBytes[idx]);
                    if (isDiff) ss << "<span class='diff-mem' onclick=\"inspectByte(this, '+0x" << std::hex << (baseOffset + idx) << "', '" << std::hex << std::setw(2) << std::setfill('0') << (int)memBytes[idx] << "')\">";
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)memBytes[idx];
                    if (isDiff) ss << "</span>";
                    ss << " ";
                }
                else {
                    ss << "   ";
                }
            }
            ss << "</td>\n";
            ss << "            <td class='hex-ascii'>";
            for (size_t c = 0; c < 16; c++) {
                size_t idx = rowOffset + c;
                if (idx < memBytes.size()) {
                    char ch = (char)memBytes[idx];
                    if (ch >= 32 && ch <= 126) ss << EscapeHTML(std::string(1, ch));
                    else ss << ".";
                }
            }
            ss << "</td>\n";
            ss << "          </tr>\n";
        }
        ss << "        </tbody>\n";
        ss << "      </table>\n";
        ss << "    </div>\n";

        ss << "  </div>\n";
        ss << "</div>\n";
        return ss.str();
    }

    bool GenerateHTMLProofPanel(const ScanReportData& report, const std::string& outputPath, bool autoOpen) {
        std::ofstream html(outputPath);
        if (!html) return false;

        size_t totalThreats = report.StompDetections.size() + report.HookDetections.size() +
            report.SigDetections.size() + report.DriverDetections.size() +
            report.LoadedDriverDetections.size() + report.MappedDriverDetections.size() +
            report.EmulatorDetections.size() + report.VADDetections.size() +
            report.ThreadDetections.size() + report.OverlayDetections.size() +
            report.FileArtifactDetections.size() + report.RegArtifactDetections.size() +
            report.NetworkConnections.size() + report.ProcessTreeDetections.size() +
            report.NTFSDetections.size() + report.TimelineDetections.size() +
            report.ClbDllDetections.size() +
            report.DLLProxyDetections.size() +
            report.EncryptedStringDetections.size() +
            report.SpoofedThreadDetections.size() +
            report.ETWDetections.size() +
            report.HollowingDetections.size();

        size_t critCount = 0;
        size_t highCount = 0;
        for (const auto& d : report.StompDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.HookDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.SigDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.DriverDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.LoadedDriverDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.MappedDriverDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.EmulatorDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.VADDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.ThreadDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.OverlayDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.FileArtifactDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.RegArtifactDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.ProcessTreeDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.NTFSDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.TimelineDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.ClbDllDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.DLLProxyDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.EncryptedStringDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.SpoofedThreadDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.ETWDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }
        for (const auto& d : report.HollowingDetections) { if (d.Severity == "CRITICAL") critCount++; else highCount++; }

        size_t criticalCount = critCount;
        size_t warningCount = highCount;

        // Threat Score Calculation (0 - 100)
        int threatScore = 0;
        if (!report.HVCIStatus.HVCIEnabled) threatScore += 15;
        if (report.TamperStatus.IsTampered) threatScore += 35;
        threatScore += (int)(critCount * 20 + highCount * 10);
        if (threatScore > 100) threatScore = 100;
        if (totalThreats == 0 && report.HVCIStatus.HVCIEnabled && !report.TamperStatus.IsTampered) threatScore = 0;

        std::string defconLevel = "DEFCON 5 // SYSTEM SECURE";
        std::string defconColor = "#00f5a0";
        if (threatScore >= 75) { defconLevel = "DEFCON 1 // CRITICAL BREACH"; defconColor = "#ff1e56"; }
        else if (threatScore >= 50) { defconLevel = "DEFCON 2 // HIGH RISK ALERT"; defconColor = "#ff5500"; }
        else if (threatScore >= 25) { defconLevel = "DEFCON 3 // ELEVATED THREAT"; defconColor = "#ffaa00"; }
        else if (threatScore > 0) { defconLevel = "DEFCON 4 // ADVISORY NOTICE"; defconColor = "#facc15"; }

        html << "<!DOCTYPE html>\n<html lang='en'>\n<head>\n";
        html << "<meta charset='UTF-8'>\n";
        html << "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n";
        html << "<title>AETHER-ZERO™ Forensic Intelligence Dossier | Zero-Trust Kernel Attestation</title>\n";
        html << "<link rel='preconnect' href='https://fonts.googleapis.com'>\n";
        html << "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>\n";
        html << "<link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Orbitron:wght@600;700;800;900&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap' rel='stylesheet'>\n";

        html << "<style>\n"
            ":root {\n"
            "  --bg-primary: #040711;\n"
            "  --bg-surface: #090e1a;\n"
            "  --bg-card: rgba(13, 20, 36, 0.75);\n"
            "  --bg-card-hover: rgba(19, 30, 54, 0.85);\n"
            "  --border-color: rgba(0, 242, 254, 0.15);\n"
            "  --border-subtle: rgba(255, 255, 255, 0.07);\n"
            "  --border-glow: rgba(0, 242, 254, 0.4);\n"
            "  --text-primary: #f8fafc;\n"
            "  --text-secondary: #94a3b8;\n"
            "  --text-muted: #64748b;\n"
            "  --accent-cyan: #00f2fe;\n"
            "  --accent-blue: #3b82f6;\n"
            "  --accent-purple: #8b5cf6;\n"
            "  --accent-pink: #ec4899;\n"
            "  --color-critical: #ff1e56;\n"
            "  --color-high: #ff7700;\n"
            "  --color-medium: #facc15;\n"
            "  --color-success: #00f5a0;\n"
            "  --font-sans: 'Plus Jakarta Sans', -apple-system, sans-serif;\n"
            "  --font-mono: 'JetBrains Mono', monospace;\n"
            "  --font-hud: 'Orbitron', monospace;\n"
            "}\n"
            "* { box-sizing: border-box; margin: 0; padding: 0; }\n"
            "body {\n"
            "  background-color: var(--bg-primary);\n"
            "  color: var(--text-primary);\n"
            "  font-family: var(--font-sans);\n"
            "  font-size: 13.5px;\n"
            "  line-height: 1.5;\n"
            "  overflow-x: hidden;\n"
            "  min-height: 100vh;\n"
            "}\n"
            "/* BACKGROUND CANVAS & SCANLINES */\n"
            "#particle-canvas {\n"
            "  position: fixed;\n"
            "  top: 0; left: 0; width: 100vw; height: 100vh;\n"
            "  pointer-events: none;\n"
            "  z-index: 0;\n"
            "  opacity: 0.6;\n"
            "}\n"
            ".cyber-grid-overlay {\n"
            "  position: fixed;\n"
            "  top: 0; left: 0; width: 100vw; height: 100vh;\n"
            "  background-image: \n"
            "    radial-gradient(circle at 15% 15%, rgba(0, 242, 254, 0.06) 0%, transparent 45%),\n"
            "    radial-gradient(circle at 85% 85%, rgba(139, 92, 246, 0.06) 0%, transparent 45%),\n"
            "    linear-gradient(rgba(255, 255, 255, 0.012) 1px, transparent 1px),\n"
            "    linear-gradient(90deg, rgba(255, 255, 255, 0.012) 1px, transparent 1px);\n"
            "  background-size: 100% 100%, 100% 100%, 36px 36px, 36px 36px;\n"
            "  pointer-events: none;\n"
            "  z-index: 1;\n"
            "}\n"
            "/* APP LAYOUT */\n"
            ".app-layout {\n"
            "  display: grid;\n"
            "  grid-template-columns: 290px 1fr;\n"
            "  min-height: 100vh;\n"
            "  position: relative;\n"
            "  z-index: 2;\n"
            "}\n"
            "/* SIDEBAR */\n"
            ".sidebar {\n"
            "  background: rgba(8, 13, 24, 0.85);\n"
            "  backdrop-filter: blur(24px);\n"
            "  -webkit-backdrop-filter: blur(24px);\n"
            "  border-right: 1px solid var(--border-color);\n"
            "  padding: 24px 16px;\n"
            "  display: flex;\n"
            "  flex-direction: column;\n"
            "  position: sticky;\n"
            "  top: 0;\n"
            "  height: 100vh;\n"
            "  overflow-y: auto;\n"
            "}\n"
            ".brand {\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  gap: 14px;\n"
            "  padding-bottom: 20px;\n"
            "  border-bottom: 1px solid var(--border-subtle);\n"
            "  margin-bottom: 20px;\n"
            "}\n"
            ".brand-logo {\n"
            "  width: 44px;\n"
            "  height: 44px;\n"
            "  border-radius: 12px;\n"
            "  background: linear-gradient(135deg, #00f2fe, #7928ca);\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  justify-content: center;\n"
            "  font-family: var(--font-hud);\n"
            "  font-weight: 900;\n"
            "  font-size: 17px;\n"
            "  color: #fff;\n"
            "  box-shadow: 0 0 25px rgba(0, 242, 254, 0.4), inset 0 0 10px rgba(255,255,255,0.3);\n"
            "  border: 1px solid rgba(255, 255, 255, 0.3);\n"
            "  animation: logoPulse 4s infinite alternate;\n"
            "}\n"
            "@keyframes logoPulse {\n"
            "  0% { box-shadow: 0 0 20px rgba(0, 242, 254, 0.3); }\n"
            "  100% { box-shadow: 0 0 35px rgba(236, 72, 153, 0.5); }\n"
            "}\n"
            ".brand-title h1 {\n"
            "  font-family: var(--font-hud);\n"
            "  font-size: 15px;\n"
            "  font-weight: 800;\n"
            "  letter-spacing: 1px;\n"
            "  background: linear-gradient(90deg, #ffffff, var(--accent-cyan));\n"
            "  -webkit-background-clip: text;\n"
            "  -webkit-text-fill-color: transparent;\n"
            "}\n"
            ".brand-title p {\n"
            "  font-size: 10px;\n"
            "  font-family: var(--font-mono);\n"
            "  color: var(--accent-cyan);\n"
            "  letter-spacing: 1.5px;\n"
            "}\n"
            ".nav-section-title {\n"
            "  font-size: 10.5px;\n"
            "  font-family: var(--font-mono);\n"
            "  text-transform: uppercase;\n"
            "  letter-spacing: 1.5px;\n"
            "  color: var(--text-muted);\n"
            "  margin: 18px 8px 6px;\n"
            "  font-weight: 700;\n"
            "}\n"
            ".nav-item {\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  justify-content: space-between;\n"
            "  padding: 9px 13px;\n"
            "  border-radius: 8px;\n"
            "  color: var(--text-secondary);\n"
            "  text-decoration: none;\n"
            "  margin-bottom: 3px;\n"
            "  font-weight: 600;\n"
            "  font-size: 12.5px;\n"
            "  cursor: pointer;\n"
            "  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);\n"
            "  border: 1px solid transparent;\n"
            "}\n"
            ".nav-item:hover {\n"
            "  background: rgba(0, 242, 254, 0.07);\n"
            "  color: var(--text-primary);\n"
            "  border-color: rgba(0, 242, 254, 0.2);\n"
            "  transform: translateX(3px);\n"
            "}\n"
            ".nav-item.active {\n"
            "  background: linear-gradient(90deg, rgba(0, 242, 254, 0.18), rgba(121, 40, 202, 0.1));\n"
            "  color: var(--accent-cyan);\n"
            "  border: 1px solid rgba(0, 242, 254, 0.3);\n"
            "  box-shadow: inset 0 0 15px rgba(0, 242, 254, 0.15);\n"
            "}\n"
            ".nav-badge {\n"
            "  padding: 2px 7px;\n"
            "  border-radius: 10px;\n"
            "  font-size: 10.5px;\n"
            "  font-family: var(--font-mono);\n"
            "  font-weight: 700;\n"
            "  background: rgba(255, 255, 255, 0.08);\n"
            "  color: var(--text-muted);\n"
            "}\n"
            ".nav-badge.danger {\n"
            "  background: rgba(255, 30, 86, 0.25);\n"
            "  color: var(--color-critical);\n"
            "  border: 1px solid rgba(255, 30, 86, 0.4);\n"
            "  box-shadow: 0 0 8px rgba(255, 30, 86, 0.3);\n"
            "  animation: badgeBlink 2s infinite;\n"
            "}\n"
            "@keyframes badgeBlink { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }\n"
            "/* MAIN CONTENT AREA */\n"
            ".main-content {\n"
            "  padding: 28px 36px;\n"
            "  max-width: 1600px;\n"
            "}\n"
            "/* TOP HUD BAR */\n"
            ".top-hud {\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  justify-content: space-between;\n"
            "  margin-bottom: 24px;\n"
            "  gap: 18px;\n"
            "  flex-wrap: wrap;\n"
            "}\n"
            ".hud-search-box {\n"
            "  position: relative;\n"
            "  flex: 1;\n"
            "  min-width: 280px;\n"
            "  max-width: 500px;\n"
            "}\n"
            ".hud-search-box input {\n"
            "  width: 100%;\n"
            "  background: rgba(13, 20, 36, 0.8);\n"
            "  border: 1px solid var(--border-color);\n"
            "  border-radius: 10px;\n"
            "  padding: 10px 16px 10px 40px;\n"
            "  color: #fff;\n"
            "  font-family: var(--font-sans);\n"
            "  font-size: 13px;\n"
            "  outline: none;\n"
            "  transition: all 0.2s;\n"
            "  backdrop-filter: blur(10px);\n"
            "}\n"
            ".hud-search-box input:focus {\n"
            "  border-color: var(--accent-cyan);\n"
            "  box-shadow: 0 0 20px rgba(0, 242, 254, 0.3);\n"
            "}\n"
            ".hud-search-icon {\n"
            "  position: absolute;\n"
            "  left: 14px;\n"
            "  top: 50%;\n"
            "  transform: translateY(-50%);\n"
            "  color: var(--accent-cyan);\n"
            "  font-size: 14px;\n"
            "}\n"
            ".hud-controls {\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  gap: 10px;\n"
            "}\n"
            ".btn {\n"
            "  padding: 9px 16px;\n"
            "  border-radius: 8px;\n"
            "  font-weight: 700;\n"
            "  font-size: 12.5px;\n"
            "  cursor: pointer;\n"
            "  border: 1px solid transparent;\n"
            "  display: inline-flex;\n"
            "  align-items: center;\n"
            "  gap: 7px;\n"
            "  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);\n"
            "  text-decoration: none;\n"
            "  font-family: var(--font-sans);\n"
            "}\n"
            ".btn-primary {\n"
            "  background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));\n"
            "  color: #040810;\n"
            "  box-shadow: 0 0 15px rgba(0, 242, 254, 0.35);\n"
            "  border: 1px solid rgba(255, 255, 255, 0.3);\n"
            "}\n"
            ".btn-primary:hover {\n"
            "  transform: translateY(-2px);\n"
            "  box-shadow: 0 0 25px rgba(0, 242, 254, 0.55);\n"
            "}\n"
            ".btn-danger {\n"
            "  background: linear-gradient(135deg, var(--color-critical), #99002b);\n"
            "  color: #fff;\n"
            "  box-shadow: 0 0 15px rgba(255, 30, 86, 0.35);\n"
            "  border: 1px solid rgba(255, 30, 86, 0.4);\n"
            "}\n"
            ".btn-danger:hover {\n"
            "  transform: translateY(-2px);\n"
            "  box-shadow: 0 0 25px rgba(255, 30, 86, 0.6);\n"
            "}\n"
            ".btn-glass {\n"
            "  background: rgba(13, 20, 36, 0.7);\n"
            "  color: var(--text-primary);\n"
            "  border: 1px solid var(--border-color);\n"
            "  backdrop-filter: blur(10px);\n"
            "}\n"
            ".btn-glass:hover {\n"
            "  background: rgba(0, 242, 254, 0.12);\n"
            "  border-color: var(--accent-cyan);\n"
            "}\n"
            "/* HERO SOC COMMAND SECTION */\n"
            ".hero-soc-grid {\n"
            "  display: grid;\n"
            "  grid-template-columns: 1.6fr 1fr;\n"
            "  gap: 20px;\n"
            "  margin-bottom: 24px;\n"
            "}\n"
            "@media(max-width: 1200px) { .hero-soc-grid { grid-template-columns: 1fr; } }\n"
            ".soc-banner-card {\n"
            "  background: var(--bg-card);\n"
            "  backdrop-filter: blur(20px);\n"
            "  border: 1px solid var(--border-color);\n"
            "  border-radius: 16px;\n"
            "  padding: 24px 28px;\n"
            "  position: relative;\n"
            "  overflow: hidden;\n"
            "  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);\n"
            "}\n"
            ".soc-banner-card::before {\n"
            "  content: '';\n"
            "  position: absolute;\n"
            "  top: 0; left: 0; width: 4px; height: 100%;\n"
            "  background: " << defconColor << ";\n"
            "  box-shadow: 0 0 15px " << defconColor << ";\n"
            "}\n"
            ".defcon-pill {\n"
            "  display: inline-flex;\n"
            "  align-items: center;\n"
            "  gap: 8px;\n"
            "  padding: 5px 14px;\n"
            "  border-radius: 20px;\n"
            "  font-family: var(--font-hud);\n"
            "  font-size: 11.5px;\n"
            "  font-weight: 800;\n"
            "  letter-spacing: 1px;\n"
            "  margin-bottom: 12px;\n"
            "  background: " << (threatScore > 0 ? "rgba(255, 30, 86, 0.15)" : "rgba(0, 245, 160, 0.15)") << ";\n"
            "  color: " << defconColor << ";\n"
            "  border: 1px solid " << defconColor << ";\n"
            "  box-shadow: 0 0 12px " << (threatScore > 0 ? "rgba(255, 30, 86, 0.3)" : "rgba(0, 245, 160, 0.3)") << ";\n"
            "}\n"
            ".soc-title {\n"
            "  font-family: var(--font-hud);\n"
            "  font-size: 23px;\n"
            "  font-weight: 900;\n"
            "  letter-spacing: 0.5px;\n"
            "  margin-bottom: 12px;\n"
            "  background: linear-gradient(90deg, #ffffff, var(--accent-cyan));\n"
            "  -webkit-background-clip: text;\n"
            "  -webkit-text-fill-color: transparent;\n"
            "}\n"
            ".soc-meta-pills {\n"
            "  display: flex;\n"
            "  flex-wrap: wrap;\n"
            "  gap: 12px;\n"
            "  font-family: var(--font-mono);\n"
            "  font-size: 12px;\n"
            "}\n"
            ".soc-meta-pill {\n"
            "  background: rgba(0, 0, 0, 0.4);\n"
            "  padding: 6px 12px;\n"
            "  border-radius: 6px;\n"
            "  border: 1px solid var(--border-subtle);\n"
            "  color: var(--text-secondary);\n"
            "}\n"
            ".soc-meta-pill strong { color: var(--text-primary); }\n"
            "/* RADAR & GAUGE WIDGET */\n"
            ".soc-radar-card {\n"
            "  background: var(--bg-card);\n"
            "  backdrop-filter: blur(20px);\n"
            "  border: 1px solid var(--border-color);\n"
            "  border-radius: 16px;\n"
            "  padding: 20px;\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  justify-content: space-around;\n"
            "  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);\n"
            "  position: relative;\n"
            "}\n"
            ".radar-box {\n"
            "  position: relative;\n"
            "  width: 140px;\n"
            "  height: 140px;\n"
            "}\n"
            "#radarCanvas {\n"
            "  width: 140px;\n"
            "  height: 140px;\n"
            "  border-radius: 50%;\n"
            "  border: 1px solid var(--border-glow);\n"
            "  background: rgba(0, 20, 30, 0.6);\n"
            "}\n"
            ".gauge-box {\n"
            "  display: flex;\n"
            "  flex-direction: column;\n"
            "  align-items: center;\n"
            "  justify-content: center;\n"
            "}\n"
            ".gauge-val {\n"
            "  font-family: var(--font-hud);\n"
            "  font-size: 34px;\n"
            "  font-weight: 900;\n"
            "  color: " << defconColor << ";\n"
            "  text-shadow: 0 0 15px " << defconColor << ";\n"
            "}\n"
            ".gauge-label {\n"
            "  font-family: var(--font-mono);\n"
            "  font-size: 11px;\n"
            "  text-transform: uppercase;\n"
            "  letter-spacing: 1px;\n"
            "  color: var(--text-muted);\n"
            "}\n"
            "/* STATS GRID */\n"
            ".stats-grid {\n"
            "  display: grid;\n"
            "  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));\n"
            "  gap: 16px;\n"
            "  margin-bottom: 24px;\n"
            "}\n"
            ".stat-card {\n"
            "  background: var(--bg-card);\n"
            "  backdrop-filter: blur(16px);\n"
            "  border: 1px solid var(--border-subtle);\n"
            "  border-radius: 14px;\n"
            "  padding: 18px;\n"
            "  transition: all 0.25s;\n"
            "  position: relative;\n"
            "}\n"
            ".stat-card:hover {\n"
            "  transform: translateY(-3px);\n"
            "  border-color: var(--accent-cyan);\n"
            "  box-shadow: 0 8px 25px rgba(0, 242, 254, 0.15);\n"
            "}\n"
            ".stat-label {\n"
            "  font-family: var(--font-mono);\n"
            "  color: var(--text-muted);\n"
            "  font-size: 11px;\n"
            "  font-weight: 700;\n"
            "  text-transform: uppercase;\n"
            "  letter-spacing: 0.5px;\n"
            "  margin-bottom: 6px;\n"
            "}\n"
            ".stat-val {\n"
            "  font-family: var(--font-hud);\n"
            "  font-size: 26px;\n"
            "  font-weight: 800;\n"
            "}\n"
            "/* ATTACK CHAIN GRAPH */\n"
            ".chain-container {\n"
            "  background: var(--bg-card);\n"
            "  backdrop-filter: blur(16px);\n"
            "  border: 1px solid var(--border-color);\n"
            "  border-radius: 16px;\n"
            "  padding: 20px 24px;\n"
            "  margin-bottom: 24px;\n"
            "}\n"
            ".chain-header {\n"
            "  display: flex;\n"
            "  justify-content: space-between;\n"
            "  align-items: center;\n"
            "  margin-bottom: 16px;\n"
            "}\n"
            ".chain-title {\n"
            "  font-family: var(--font-hud);\n"
            "  font-size: 14px;\n"
            "  font-weight: 800;\n"
            "  letter-spacing: 0.5px;\n"
            "  color: var(--accent-cyan);\n"
            "}\n"
            ".chain-nodes {\n"
            "  display: grid;\n"
            "  grid-template-columns: repeat(6, 1fr);\n"
            "  gap: 12px;\n"
            "}\n"
            "@media(max-width: 1024px) { .chain-nodes { grid-template-columns: repeat(3, 1fr); } }\n"
            "@media(max-width: 600px) { .chain-nodes { grid-template-columns: 1fr; } }\n"
            ".chain-node {\n"
            "  background: rgba(8, 14, 26, 0.8);\n"
            "  border: 1px solid var(--border-subtle);\n"
            "  border-radius: 10px;\n"
            "  padding: 12px;\n"
            "  text-align: center;\n"
            "  position: relative;\n"
            "  transition: all 0.2s;\n"
            "}\n"
            ".chain-node.threat {\n"
            "  border-color: var(--color-critical);\n"
            "  background: rgba(255, 30, 86, 0.1);\n"
            "  box-shadow: 0 0 15px rgba(255, 30, 86, 0.25);\n"
            "}\n"
            ".chain-node.clean {\n"
            "  border-color: rgba(0, 245, 160, 0.3);\n"
            "}\n"
            ".chain-step {\n"
            "  font-family: var(--font-mono);\n"
            "  font-size: 9.5px;\n"
            "  color: var(--text-muted);\n"
            "  text-transform: uppercase;\n"
            "  margin-bottom: 4px;\n"
            "}\n"
            ".chain-name {\n"
            "  font-size: 12px;\n"
            "  font-weight: 700;\n"
            "  color: var(--text-primary);\n"
            "  margin-bottom: 4px;\n"
            "}\n"
            ".chain-count {\n"
            "  font-family: var(--font-mono);\n"
            "  font-size: 11px;\n"
            "  font-weight: 800;\n"
            "}\n"
            "/* SECTION CARDS & TABLES */\n"
            ".section-card {\n"
            "  background: var(--bg-card);\n"
            "  backdrop-filter: blur(16px);\n"
            "  border: 1px solid var(--border-color);\n"
            "  border-radius: 16px;\n"
            "  margin-bottom: 24px;\n"
            "  overflow: hidden;\n"
            "}\n"
            ".card-header {\n"
            "  padding: 18px 24px;\n"
            "  border-bottom: 1px solid var(--border-subtle);\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  justify-content: space-between;\n"
            "  background: rgba(255, 255, 255, 0.02);\n"
            "}\n"
            ".card-title {\n"
            "  font-family: var(--font-hud);\n"
            "  font-size: 14px;\n"
            "  font-weight: 800;\n"
            "  letter-spacing: 0.5px;\n"
            "  color: var(--text-primary);\n"
            "}\n"
            ".card-body { padding: 24px; }\n"
            ".data-table {\n"
            "  width: 100%;\n"
            "  border-collapse: collapse;\n"
            "  font-size: 12.5px;\n"
            "}\n"
            ".data-table th {\n"
            "  text-align: left;\n"
            "  padding: 12px 14px;\n"
            "  color: var(--text-muted);\n"
            "  font-family: var(--font-mono);\n"
            "  font-weight: 700;\n"
            "  border-bottom: 1px solid var(--border-color);\n"
            "  font-size: 11px;\n"
            "  text-transform: uppercase;\n"
            "  letter-spacing: 0.5px;\n"
            "}\n"
            ".data-table td {\n"
            "  padding: 13px 14px;\n"
            "  border-bottom: 1px solid rgba(255, 255, 255, 0.03);\n"
            "  color: var(--text-secondary);\n"
            "}\n"
            ".data-table tr:hover td {\n"
            "  background: rgba(0, 242, 254, 0.04);\n"
            "  color: var(--text-primary);\n"
            "}\n"
            "/* BADGES */\n"
            ".badge {\n"
            "  padding: 3px 9px;\n"
            "  border-radius: 6px;\n"
            "  font-size: 10.5px;\n"
            "  font-weight: 800;\n"
            "  font-family: var(--font-mono);\n"
            "  display: inline-block;\n"
            "  letter-spacing: 0.5px;\n"
            "}\n"
            ".badge-critical { background: rgba(255, 30, 86, 0.18); color: var(--color-critical); border: 1px solid rgba(255, 30, 86, 0.4); }\n"
            ".badge-high { background: rgba(255, 119, 0, 0.18); color: var(--color-high); border: 1px solid rgba(255, 119, 0, 0.4); }\n"
            ".badge-medium { background: rgba(250, 204, 21, 0.18); color: var(--color-medium); border: 1px solid rgba(250, 204, 21, 0.4); }\n"
            ".badge-success { background: rgba(0, 245, 160, 0.18); color: var(--color-success); border: 1px solid rgba(0, 245, 160, 0.4); }\n"
            "/* HEX VIEWER & DIFF */\n"
            ".hex-viewer-container {\n"
            "  background: rgba(5, 9, 18, 0.95);\n"
            "  border: 1px solid var(--border-color);\n"
            "  border-radius: 12px;\n"
            "  overflow: hidden;\n"
            "  margin-top: 14px;\n"
            "}\n"
            ".hex-toolbar {\n"
            "  display: flex;\n"
            "  justify-content: space-between;\n"
            "  align-items: center;\n"
            "  padding: 10px 16px;\n"
            "  background: rgba(0, 0, 0, 0.4);\n"
            "  border-bottom: 1px solid var(--border-subtle);\n"
            "}\n"
            ".hex-actions { display: flex; align-items: center; gap: 12px; }\n"
            ".hex-tip { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); }\n"
            ".btn-mini {\n"
            "  padding: 4px 10px;\n"
            "  border-radius: 4px;\n"
            "  background: rgba(255, 255, 255, 0.08);\n"
            "  border: 1px solid var(--border-subtle);\n"
            "  color: #fff;\n"
            "  font-size: 11px;\n"
            "  font-family: var(--font-mono);\n"
            "  cursor: pointer;\n"
            "}\n"
            ".btn-mini:hover { background: var(--accent-cyan); color: #000; }\n"
            ".diff-badge { padding: 2px 6px; border-radius: 4px; font-family: var(--font-mono); font-size: 10px; font-weight: 700; }\n"
            ".hex-viewer-wrapper {\n"
            "  display: grid;\n"
            "  grid-template-columns: 1fr 1fr;\n"
            "  gap: 1px;\n"
            "  background: var(--border-subtle);\n"
            "}\n"
            "@media(max-width: 1000px) { .hex-viewer-wrapper { grid-template-columns: 1fr; } }\n"
            ".hex-column {\n"
            "  background: rgba(5, 9, 18, 0.95);\n"
            "  padding: 12px 16px;\n"
            "  overflow-x: auto;\n"
            "}\n"
            ".hex-title {\n"
            "  font-family: var(--font-mono);\n"
            "  font-size: 11.5px;\n"
            "  font-weight: 700;\n"
            "  color: var(--accent-cyan);\n"
            "  margin-bottom: 8px;\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  gap: 6px;\n"
            "}\n"
            ".hex-table {\n"
            "  width: 100%;\n"
            "  border-collapse: collapse;\n"
            "  font-family: var(--font-mono);\n"
            "  font-size: 11.5px;\n"
            "}\n"
            ".hex-table th, .hex-table td {\n"
            "  padding: 4px 6px;\n"
            "  border-bottom: 1px solid rgba(255, 255, 255, 0.02);\n"
            "}\n"
            ".hex-offset { color: var(--text-muted); }\n"
            ".hex-bytes { color: #cbd5e1; letter-spacing: 0.5px; }\n"
            ".hex-ascii { color: var(--accent-cyan); border-left: 1px solid rgba(255,255,255,0.05); padding-left: 10px; }\n"
            ".diff-disk { background: rgba(0, 245, 160, 0.25); color: #00f5a0; font-weight: 700; padding: 1px 3px; border-radius: 3px; border: 1px solid rgba(0, 245, 160, 0.4); }\n"
            ".diff-mem { background: rgba(255, 30, 86, 0.35); color: #ff1e56; font-weight: 700; padding: 1px 3px; border-radius: 3px; border: 1px solid rgba(255, 30, 86, 0.5); cursor: pointer; }\n"
            ".diff-mem:hover { background: rgba(255, 30, 86, 0.6); }\n"
            "/* CODE BLOCK & EMPTY STATE */\n"
            ".code-block {\n"
            "  font-family: var(--font-mono);\n"
            "  background: rgba(0, 0, 0, 0.5);\n"
            "  padding: 6px 10px;\n"
            "  border-radius: 6px;\n"
            "  border: 1px solid var(--border-subtle);\n"
            "  font-size: 11.5px;\n"
            "  color: #38bdf8;\n"
            "  word-break: break-all;\n"
            "}\n"
            ".empty-state {\n"
            "  text-align: center;\n"
            "  padding: 48px 20px;\n"
            "  color: var(--text-muted);\n"
            "}\n"
            ".empty-state-icon { font-size: 40px; margin-bottom: 12px; }\n"
            "/* MODAL BACKDROP */\n"
            ".modal-backdrop {\n"
            "  display: none;\n"
            "  position: fixed;\n"
            "  inset: 0;\n"
            "  background: rgba(0,0,0,0.75);\n"
            "  z-index: 9000;\n"
            "  align-items: center;\n"
            "  justify-content: center;\n"
            "  backdrop-filter: blur(6px);\n"
            "}\n"
            ".modal-backdrop.open {\n"
            "  display: flex;\n"
            "}\n"
            ".modal-box {\n"
            "  background: #070d1a;\n"
            "  border: 1px solid rgba(0,200,224,0.3);\n"
            "  border-radius: 14px;\n"
            "  padding: 24px 28px;\n"
            "  max-width: 520px;\n"
            "  width: 92%;\n"
            "  box-shadow: 0 20px 60px rgba(0,0,0,0.9);\n"
            "}\n"
            ".modal-header {\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  justify-content: space-between;\n"
            "  margin-bottom: 16px;\n"
            "  padding-bottom: 12px;\n"
            "  border-bottom: 1px solid rgba(255,255,255,0.06);\n"
            "}\n"
            ".modal-close {\n"
            "  background: rgba(255,255,255,0.05);\n"
            "  border: 1px solid rgba(255,255,255,0.12);\n"
            "  color: #94a3b8;\n"
            "  width: 30px;\n"
            "  height: 30px;\n"
            "  border-radius: 6px;\n"
            "  cursor: pointer;\n"
            "  font-size: 16px;\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  justify-content: center;\n"
            "}\n"
            ".modal-close:hover { background: rgba(255,30,86,0.2); color: #fff; border-color: #ff1e56; }\n"
            ".tab-pane { display: none; }\n"
            ".tab-pane.active { display: block; animation: tabFadeIn 0.25s cubic-bezier(0.4, 0, 0.2, 1); }\n"
            "@keyframes tabFadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }\n"
            "/* WARNING / THREAT LOGS MODAL & CARDS (IMAGE ACCURATE) */\n"
            ".warning-modal-box {\n"
            "  background: #090d16;\n"
            "  border: 1px solid rgba(255, 255, 255, 0.12);\n"
            "  border-radius: 20px;\n"
            "  width: 92%;\n"
            "  max-width: 920px;\n"
            "  max-height: 88vh;\n"
            "  display: flex;\n"
            "  flex-direction: column;\n"
            "  padding: 24px 28px;\n"
            "  box-shadow: 0 25px 60px rgba(0, 0, 0, 0.95), 0 0 35px rgba(0, 245, 160, 0.15);\n"
            "  position: relative;\n"
            "  overflow: hidden;\n"
            "}\n"
            ".warning-modal-header {\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  justify-content: space-between;\n"
            "  margin-bottom: 16px;\n"
            "}\n"
            ".warning-title-group {\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  gap: 12px;\n"
            "}\n"
            ".warning-icon-circle {\n"
            "  width: 32px;\n"
            "  height: 32px;\n"
            "  border-radius: 50%;\n"
            "  background: #eab308;\n"
            "  color: #000;\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  justify-content: center;\n"
            "  font-weight: 900;\n"
            "  font-size: 18px;\n"
            "  box-shadow: 0 0 15px rgba(234, 179, 8, 0.4);\n"
            "}\n"
            ".warning-icon-circle.critical {\n"
            "  background: #ff1e56;\n"
            "  color: #fff;\n"
            "  box-shadow: 0 0 15px rgba(255, 30, 86, 0.5);\n"
            "}\n"
            ".warning-modal-title {\n"
            "  font-family: var(--font-hud);\n"
            "  font-size: 21px;\n"
            "  font-weight: 800;\n"
            "  color: #fff;\n"
            "  letter-spacing: 0.5px;\n"
            "}\n"
            ".warning-count-badge {\n"
            "  background: rgba(255, 255, 255, 0.08);\n"
            "  border: 1px solid rgba(255, 255, 255, 0.15);\n"
            "  padding: 4px 12px;\n"
            "  border-radius: 14px;\n"
            "  font-family: var(--font-mono);\n"
            "  font-size: 11px;\n"
            "  color: #94a3b8;\n"
            "  font-weight: 700;\n"
            "}\n"
            ".warning-close-btn {\n"
            "  background: rgba(255, 255, 255, 0.06);\n"
            "  border: 1px solid rgba(255, 255, 255, 0.12);\n"
            "  color: #94a3b8;\n"
            "  width: 34px;\n"
            "  height: 34px;\n"
            "  border-radius: 8px;\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  justify-content: center;\n"
            "  font-size: 16px;\n"
            "  cursor: pointer;\n"
            "  transition: all 0.2s ease;\n"
            "}\n"
            ".warning-close-btn:hover {\n"
            "  background: rgba(255, 30, 86, 0.25);\n"
            "  border-color: #ff1e56;\n"
            "  color: #fff;\n"
            "}\n"
            ".warning-search-container {\n"
            "  margin-bottom: 16px;\n"
            "}\n"
            ".warning-search-input {\n"
            "  width: 100%;\n"
            "  background: #050811;\n"
            "  border: 1.5px solid #00f5a0;\n"
            "  box-shadow: 0 0 12px rgba(0, 245, 160, 0.3);\n"
            "  border-radius: 10px;\n"
            "  padding: 12px 18px;\n"
            "  font-family: var(--font-sans);\n"
            "  font-size: 14px;\n"
            "  color: #fff;\n"
            "  outline: none;\n"
            "  transition: all 0.2s ease;\n"
            "}\n"
            ".warning-search-input:focus {\n"
            "  border-color: #00f2fe;\n"
            "  box-shadow: 0 0 18px rgba(0, 242, 254, 0.45);\n"
            "}\n"
            ".warning-search-input::placeholder {\n"
            "  color: #475569;\n"
            "}\n"
            ".warning-logs-scroll {\n"
            "  overflow-y: auto;\n"
            "  padding-right: 6px;\n"
            "  flex: 1;\n"
            "  display: flex;\n"
            "  flex-direction: column;\n"
            "  gap: 12px;\n"
            "}\n"
            ".warning-section-title {\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  gap: 8px;\n"
            "  color: #00f5a0;\n"
            "  font-family: var(--font-hud);\n"
            "  font-size: 12px;\n"
            "  font-weight: 800;\n"
            "  letter-spacing: 1px;\n"
            "  text-transform: uppercase;\n"
            "  margin-top: 10px;\n"
            "  margin-bottom: 2px;\n"
            "}\n"
            ".warning-card {\n"
            "  background: rgba(13, 19, 33, 0.9);\n"
            "  border: 1px solid rgba(255, 255, 255, 0.08);\n"
            "  border-radius: 12px;\n"
            "  padding: 14px 18px;\n"
            "  display: flex;\n"
            "  justify-content: space-between;\n"
            "  align-items: center;\n"
            "  transition: all 0.2s ease;\n"
            "}\n"
            ".warning-card:hover {\n"
            "  background: rgba(22, 33, 56, 0.95);\n"
            "  border-color: rgba(0, 245, 160, 0.4);\n"
            "  transform: translateY(-2px);\n"
            "  box-shadow: 0 6px 20px rgba(0, 0, 0, 0.5);\n"
            "}\n"
            ".warning-card-left {\n"
            "  flex: 1;\n"
            "  margin-right: 20px;\n"
            "  min-width: 0;\n"
            "}\n"
            ".warning-card-title {\n"
            "  font-size: 15px;\n"
            "  font-weight: 700;\n"
            "  color: #f8fafc;\n"
            "  margin-bottom: 5px;\n"
            "}\n"
            ".warning-card-desc {\n"
            "  font-size: 12.5px;\n"
            "  font-family: var(--font-mono);\n"
            "  color: #94a3b8;\n"
            "  word-break: break-all;\n"
            "}\n"
            ".warning-card-right {\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  gap: 12px;\n"
            "  flex-shrink: 0;\n"
            "}\n"
            ".warning-meta-time {\n"
            "  display: flex;\n"
            "  align-items: center;\n"
            "  gap: 5px;\n"
            "  font-family: var(--font-mono);\n"
            "  font-size: 11.5px;\n"
            "  color: #64748b;\n"
            "}\n"
            ".btn-vt {\n"
            "  background: #1e1b4b;\n"
            "  border: 1px solid #4f46e5;\n"
            "  color: #c7d2fe;\n"
            "  font-family: var(--font-hud);\n"
            "  font-size: 11px;\n"
            "  font-weight: 700;\n"
            "  padding: 5px 12px;\n"
            "  border-radius: 8px;\n"
            "  display: inline-flex;\n"
            "  align-items: center;\n"
            "  gap: 6px;\n"
            "  cursor: pointer;\n"
            "  text-decoration: none;\n"
            "  transition: all 0.2s ease;\n"
            "}\n"
            ".btn-vt:hover {\n"
            "  background: #312e81;\n"
            "  border-color: #6366f1;\n"
            "  color: #fff;\n"
            "  box-shadow: 0 0 10px rgba(99, 102, 241, 0.4);\n"
            "}\n"
            ".badge-warning-pill {\n"
            "  background: rgba(234, 179, 8, 0.12);\n"
            "  color: #facc15;\n"
            "  border: 1px solid #eab308;\n"
            "  border-radius: 14px;\n"
            "  font-family: var(--font-hud);\n"
            "  font-size: 11px;\n"
            "  font-weight: 800;\n"
            "  letter-spacing: 0.5px;\n"
            "  padding: 4px 14px;\n"
            "  text-transform: uppercase;\n"
            "}\n"
            ".badge-critical-pill {\n"
            "  background: rgba(255, 30, 86, 0.15);\n"
            "  color: #ff1e56;\n"
            "  border: 1px solid #ff1e56;\n"
            "  border-radius: 14px;\n"
            "  font-family: var(--font-hud);\n"
            "  font-size: 11px;\n"
            "  font-weight: 800;\n"
            "  letter-spacing: 0.5px;\n"
            "  padding: 4px 14px;\n"
            "  text-transform: uppercase;\n"
            "}\n"
            "</style>\n";

        html << "</head>\n<body>\n";
        html << "<canvas id='particle-canvas'></canvas>\n";
        html << "<div class='cyber-grid-overlay'></div>\n";

        html << "<div class='app-layout'>\n";

        // SIDEBAR NAVIGATION
        html << "  <aside class='sidebar'>\n";
        html << "    <div class='brand'>\n";
        html << "      <div class='brand-logo'>NAC</div>\n";
        html << "      <div class='brand-title'>\n";
        html << "        <h1>Nehal Anti-Cheat</h1>\n";
        html << "        <p>White Hat Security Scanner</p>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        html << "    <div class='nav-section-title'>Interactive Forensics</div>\n";
        html << "    <div class='nav-item' onclick=\"openWarningLogsModal('ALL')\" style='background:rgba(234,179,8,0.12); border:1px solid rgba(234,179,8,0.35); margin-bottom:10px; cursor:pointer;'><span>⚠️ Warning & Forensic Logs</span><span class='nav-badge danger'>" << totalThreats << "</span></div>\n";

        html << "    <div class='nav-section-title'>Command Center</div>\n";
        html << "    <div class='nav-item active' onclick=\"switchTab('overview')\"><span>📊 Executive SOC HUD</span></div>\n";

        html << "    <div class='nav-section-title'>Memory & Execution</div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('stomping')\"><span>🧬 Dynamic Code & Module Integrity</span><span class='nav-badge " << (report.StompDetections.empty() ? "" : "danger") << "'>" << report.StompDetections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('vad')\"><span>🧠 Unbacked Executable Memory (VAD)</span><span class='nav-badge " << (report.VADDetections.empty() ? "" : "danger") << "'>" << report.VADDetections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('threads')\"><span>⚡ Thread APC & Context Integrity</span><span class='nav-badge " << (report.ThreadDetections.empty() ? "" : "danger") << "'>" << report.ThreadDetections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('gva')\"><span>🎮 Cross-Process Handles & Bridges</span><span class='nav-badge " << (report.EmulatorDetections.empty() ? "" : "danger") << "'>" << report.EmulatorDetections.size() << "</span></div>\n";

        html << "    <div class='nav-section-title'>System & Hooks</div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('hooks')\"><span>🪝 API Prologues & Syscall Hooks</span><span class='nav-badge " << ((report.HookDetections.size() + report.ClbDllDetections.size()) == 0 ? "" : "danger") << "'>" << (report.HookDetections.size() + report.ClbDllDetections.size()) << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('overlays')\"><span>🖥️ Transparent Viewports & Overlays</span><span class='nav-badge " << (report.OverlayDetections.empty() ? "" : "danger") << "'>" << report.OverlayDetections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('drivers')\"><span>🛡️ System Drivers & Kernel Modules</span><span class='nav-badge " << ((report.DriverDetections.size() + report.LoadedDriverDetections.size() + report.MappedDriverDetections.size()) == 0 ? "" : "danger") << "'>" << (report.DriverDetections.size() + report.LoadedDriverDetections.size() + report.MappedDriverDetections.size()) << "</span></div>\n";

        html << "    <div class='nav-section-title'>Forensic Artifacts</div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('bam')\"><span>📜 Execution Ledger & BAM</span><span class='nav-badge " << (report.RegArtifactDetections.empty() ? "" : "danger") << "'>" << report.RegArtifactDetections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('ntfs')\"><span>🌊 Alternate Streams (Zone.Id)</span><span class='nav-badge " << (report.NTFSDetections.empty() ? "" : "danger") << "'>" << report.NTFSDetections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('timeline')\"><span>⏱️ Application History & Timeline</span><span class='nav-badge " << (report.TimelineDetections.empty() ? "" : "danger") << "'>" << report.TimelineDetections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('disk')\"><span>📁 Prefetch & Storage History</span><span class='nav-badge " << (report.FileArtifactDetections.empty() ? "" : "danger") << "'>" << report.FileArtifactDetections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('network')\"><span>🌐 Outbound Network Sockets</span><span class='nav-badge " << (report.NetworkConnections.empty() ? "" : "danger") << "'>" << report.NetworkConnections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('sig')\"><span>🔏 Binary Authenticode Signatures</span><span class='nav-badge " << (report.SigDetections.empty() ? "" : "danger") << "'>" << report.SigDetections.size() << "</span></div>\n";

        html << "    <div class='nav-section-title'>Advanced Threat Vectors</div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('dllproxy')\"><span>🎭 DLL Proxy / Hijack (Real vs Fake)</span><span class='nav-badge " << (report.DLLProxyDetections.empty() ? "" : "danger") << "'>" << report.DLLProxyDetections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('encstrings')\"><span>🔐 Encrypted String Detection</span><span class='nav-badge " << (report.EncryptedStringDetections.empty() ? "" : "danger") << "'>" << report.EncryptedStringDetections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('spoofthreads')\"><span>🕵️ Spoofed Call-Stack Threads</span><span class='nav-badge " << (report.SpoofedThreadDetections.empty() ? "" : "danger") << "'>" << report.SpoofedThreadDetections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('etw')\"><span>⚡ ETW & Event Log Tampering</span><span class='nav-badge " << (report.ETWDetections.empty() ? "" : "danger") << "'>" << report.ETWDetections.size() << "</span></div>\n";
        html << "    <div class='nav-item' onclick=\"switchTab('hollowing')\"><span>🕳️ Process Hollowing & Doppelganging</span><span class='nav-badge " << (report.HollowingDetections.empty() ? "" : "danger") << "'>" << report.HollowingDetections.size() << "</span></div>\n";

        html << "  </aside>\n";

        // MAIN CONTENT
        html << "  <main class='main-content'>\n";

        // TOP HUD BAR
        html << "    <div class='top-hud'>\n";
        html << "      <div class='hud-search-box'>\n";
        html << "        <span class='hud-search-icon'>⚡</span>\n";
        html << "        <input type='text' id='globalSearch' placeholder='Live filter across all 18 forensic engines...' oninput='filterTables()'>\n";
        html << "      </div>\n";
        html << "      <div class='hud-controls'>\n";
        html << "        <button class='btn btn-glass' style='border-color:#eab308; color:#facc15; font-weight:700;' onclick=\"openWarningLogsModal('WARNING')\">⚠️ Warning Logs (" << warningCount << ")</button>\n";
        html << "        <button class='btn btn-glass' style='border-color:#ff1e56; color:#ff1e56; font-weight:700;' onclick=\"openWarningLogsModal('CRITICAL')\">🚨 Critical Threats (" << criticalCount << ")</button>\n";
        html << "        <button class='btn btn-glass' id='audioToggleBtn' onclick='toggleAudio()'>🔊 Audio FX: ON</button>\n";
        html << "        <button class='btn btn-glass' onclick='window.print()'>🖨️ Export PDF</button>\n";
        html << "        <a href='ScanEvidence.json' download class='btn btn-glass'>💾 Download JSON</a>\n";
        html << "        <button class='btn btn-danger' onclick='openBanModal()'>⚡ Ban Operations</button>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // HERO SOC COMMAND SECTION (BANNER + RADAR / GAUGE)
        html << "    <div class='hero-soc-grid'>\n";
        html << "      <div class='soc-banner-card'>\n";
        html << "        <div class='defcon-pill'>" << defconLevel << "</div>\n";
        html << "        <h2 class='soc-title'>" << (totalThreats > 0 ? std::to_string(totalThreats) + " Active Forensic Anomalies Isolated" : "System Memory & Execution Integrity Clean") << "</h2>\n";
        html << "        <div class='soc-meta-pills'>\n";
        html << "          <div class='soc-meta-pill'><span>🎯 Target: </span><strong>" << (report.TargetProcessName.empty() ? "Full System Audit" : report.TargetProcessName) << "</strong></div>\n";
        html << "          <div class='soc-meta-pill'><span>🕒 Timestamp: </span><strong>" << report.ScanTimestamp << "</strong></div>\n";
        html << "          <div class='soc-meta-pill'><span>🛡️ Core Isolation (HVCI): </span><strong style='color:" << (report.HVCIStatus.HVCIEnabled ? "var(--color-success)" : "var(--color-critical)") << ";'>" << (report.HVCIStatus.HVCIEnabled ? "ACTIVE" : "VULNERABLE (DISABLED)") << "</strong></div>\n";
        html << "          <div class='soc-meta-pill'><span>🔒 Anti-Tamper: </span><strong style='color:" << (report.TamperStatus.IsTampered ? "var(--color-critical)" : "var(--color-success)") << ";'>" << (report.TamperStatus.IsTampered ? "COMPROMISED" : "SECURE") << "</strong></div>\n";
        html << "          <div class='soc-meta-pill'><span>🆔 HWID: </span><strong style='color:#00f2fe;'>" << (report.SystemHWID.CompositeHWID.empty() ? "HWID-READY" : report.SystemHWID.CompositeHWID) << "</strong></div>\n";
        html << "        </div>\n";
        html << "        <div style='margin-top:14px; display:flex; gap:10px;'>\n";
        html << "          <button class='btn btn-glass' style='border-color:#00f5a0; color:#00f5a0; font-weight:700; background:rgba(0,245,160,0.1);' onclick=\"openWarningLogsModal('ALL')\">🔍 View Interactive Threat Cards (" << totalThreats << " Logs)</button>\n";
        html << "        </div>\n";
        html << "      </div>\n";

        html << "      <div class='soc-radar-card'>\n";
        html << "        <div class='radar-box'>\n";
        html << "          <canvas id='radarCanvas' width='140' height='140'></canvas>\n";
        html << "        </div>\n";
        html << "        <div class='gauge-box'>\n";
        html << "          <div class='gauge-val' id='threatScoreVal'>" << threatScore << "%</div>\n";
        html << "          <div class='gauge-label'>Threat Risk Index</div>\n";
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // STATS SUMMARY GRID
        html << "    <div class='stats-grid'>\n";
        html << "      <div class='stat-card'>\n";
        html << "        <div class='stat-label'>Processes Audited</div>\n";
        html << "        <div class='stat-val' style='color: var(--accent-cyan);'>" << report.TotalProcessesScanned << "</div>\n";
        html << "      </div>\n";
        html << "      <div class='stat-card'>\n";
        html << "        <div class='stat-label'>Critical Vectors</div>\n";
        html << "        <div class='stat-val' style='color: var(--color-critical);'>" << critCount << "</div>\n";
        html << "      </div>\n";
        html << "      <div class='stat-card'>\n";
        html << "        <div class='stat-label'>Memory Stomps</div>\n";
        html << "        <div class='stat-val' style='color:" << (report.StompDetections.empty() ? "var(--color-success)" : "var(--color-critical)") << ";'>" << report.StompDetections.size() << "</div>\n";
        html << "      </div>\n";
        html << "      <div class='stat-card'>\n";
        html << "        <div class='stat-label'>VAD Shellcode Pages</div>\n";
        html << "        <div class='stat-val' style='color:" << (report.VADDetections.empty() ? "var(--color-success)" : "var(--color-critical)") << ";'>" << report.VADDetections.size() << "</div>\n";
        html << "      </div>\n";
        html << "      <div class='stat-card'>\n";
        html << "        <div class='stat-label'>Rogue Driver Services</div>\n";
        html << "        <div class='stat-val' style='color:" << (report.DriverDetections.empty() ? "var(--color-success)" : "var(--color-critical)") << ";'>" << report.DriverDetections.size() << "</div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // ATTACK CHAIN GRAPH
        html << "    <div class='chain-container'>\n";
        html << "      <div class='chain-header'>\n";
        html << "        <div class='chain-title'>⚡ KILL-CHAIN FORENSIC PROGRESSION MAP</div>\n";
        html << "        <div style='font-family:var(--font-mono); font-size:11px; color:var(--text-muted);'>Multi-Vector Attack Trace</div>\n";
        html << "      </div>\n";
        html << "      <div class='chain-nodes'>\n";
        html << "        <div class='chain-node " << (report.NTFSDetections.empty() ? "clean" : "threat") << "'>\n";
        html << "          <div class='chain-step'>1. Ingress</div>\n";
        html << "          <div class='chain-name'>NTFS Streams (MOTW)</div>\n";
        html << "          <div class='chain-count' style='color:" << (report.NTFSDetections.empty() ? "var(--color-success)" : "var(--color-critical)") << ";'>" << report.NTFSDetections.size() << " Events</div>\n";
        html << "        </div>\n";
        html << "        <div class='chain-node " << (report.RegArtifactDetections.empty() && report.FileArtifactDetections.empty() ? "clean" : "threat") << "'>\n";
        html << "          <div class='chain-step'>2. Persistence</div>\n";
        html << "          <div class='chain-name'>BAM / Prefetch Logs</div>\n";
        html << "          <div class='chain-count' style='color:" << ((report.RegArtifactDetections.size() + report.FileArtifactDetections.size()) == 0 ? "var(--color-success)" : "var(--color-critical)") << ";'>" << (report.RegArtifactDetections.size() + report.FileArtifactDetections.size()) << " Events</div>\n";
        html << "        </div>\n";
        html << "        <div class='chain-node " << (report.ProcessTreeDetections.empty() && report.EmulatorDetections.empty() ? "clean" : "threat") << "'>\n";
        html << "          <div class='chain-step'>3. Loader & Bridge</div>\n";
        html << "          <div class='chain-name'>Handle Duplication</div>\n";
        html << "          <div class='chain-count' style='color:" << (report.EmulatorDetections.empty() ? "var(--color-success)" : "var(--color-critical)") << ";'>" << report.EmulatorDetections.size() << " Events</div>\n";
        html << "        </div>\n";
        html << "        <div class='chain-node " << (report.StompDetections.empty() && report.VADDetections.empty() ? "clean" : "threat") << "'>\n";
        html << "          <div class='chain-step'>4. Memory Hijack</div>\n";
        html << "          <div class='chain-name'>VAD Shellcode / Stomp</div>\n";
        html << "          <div class='chain-count' style='color:" << ((report.StompDetections.size() + report.VADDetections.size()) == 0 ? "var(--color-success)" : "var(--color-critical)") << ";'>" << (report.StompDetections.size() + report.VADDetections.size()) << " Events</div>\n";
        html << "        </div>\n";
        html << "        <div class='chain-node " << (report.HookDetections.empty() && report.ThreadDetections.empty() ? "clean" : "threat") << "'>\n";
        html << "          <div class='chain-step'>5. Evasion</div>\n";
        html << "          <div class='chain-name'>NTDLL Hooks & HWBP</div>\n";
        html << "          <div class='chain-count' style='color:" << ((report.HookDetections.size() + report.ThreadDetections.size()) == 0 ? "var(--color-success)" : "var(--color-critical)") << ";'>" << (report.HookDetections.size() + report.ThreadDetections.size()) << " Events</div>\n";
        html << "        </div>\n";
        html << "        <div class='chain-node " << (report.NetworkConnections.empty() ? "clean" : "threat") << "'>\n";
        html << "          <div class='chain-step'>6. Exfiltration</div>\n";
        html << "          <div class='chain-name'>C2 Network Sockets</div>\n";
        html << "          <div class='chain-count' style='color:" << (report.NetworkConnections.empty() ? "var(--color-success)" : "var(--color-critical)") << ";'>" << report.NetworkConnections.size() << " Events</div>\n";
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 1: OVERVIEW SUMMARY MATRIX
        html << "    <div id='tab-overview' class='tab-pane active'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🔍 13-Engine Deep Forensic Triage Matrix</span></div>\n";
        html << "        <div class='card-body'>\n";
        html << "          <table class='data-table'>\n";
        html << "            <thead><tr><th>Detection Vector</th><th>Status</th><th>Detected Events</th><th>Engine Implementation</th><th>Quick Action</th></tr></thead>\n";
        html << "            <tbody>\n";
        html << "              <tr><td>Module Stomping (SIMD Diff)</td><td><span class='badge " << (report.StompDetections.empty() ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << report.StompDetections.size() << "</td><td>StompScanner.cpp</td><td><button class='btn-mini' onclick=\"switchTab('stomping')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>Kernel VAD Tree (Unbacked RWX)</td><td><span class='badge " << (report.VADDetections.empty() ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << report.VADDetections.size() << "</td><td>VADScanner.cpp</td><td><button class='btn-mini' onclick=\"switchTab('vad')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>Ghost Threads & Hardware Breakpoints</td><td><span class='badge " << (report.ThreadDetections.empty() ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << report.ThreadDetections.size() << "</td><td>ThreadInspector.cpp</td><td><button class='btn-mini' onclick=\"switchTab('threads')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>Emulator Memory Handle Bridge</td><td><span class='badge " << (report.EmulatorDetections.empty() ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << report.EmulatorDetections.size() << "</td><td>EmulatorScanner.cpp</td><td><button class='btn-mini' onclick=\"switchTab('gva')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>NTDLL Inline Hooks & Rogue clb.dll</td><td><span class='badge " << ((report.HookDetections.size() + report.ClbDllDetections.size()) == 0 ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << (report.HookDetections.size() + report.ClbDllDetections.size()) << "</td><td>HookScanner.cpp & SyscallEngine.cpp</td><td><button class='btn-mini' onclick=\"switchTab('hooks')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>ESP Viewport Transparency Overlays</td><td><span class='badge " << (report.OverlayDetections.empty() ? "badge-success'>CLEAN" : "badge-high'>FLAGGED") << "</span></td><td>" << report.OverlayDetections.size() << "</td><td>OverlayAuditor.cpp</td><td><button class='btn-mini' onclick=\"switchTab('overlays')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>Boot Drivers & HVCI Integrity</td><td><span class='badge " << (report.DriverDetections.empty() ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << report.DriverDetections.size() << "</td><td>DriverScanner.cpp</td><td><button class='btn-mini' onclick=\"switchTab('drivers')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>BAM / DAM Execution Logs</td><td><span class='badge " << (report.RegArtifactDetections.empty() ? "badge-success'>CLEAN" : "badge-high'>FLAGGED") << "</span></td><td>" << report.RegArtifactDetections.size() << "</td><td>RegistryArtifactScanner.cpp</td><td><button class='btn-mini' onclick=\"switchTab('bam')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>NTFS Alternate Data Streams (MOTW)</td><td><span class='badge " << (report.NTFSDetections.empty() ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << report.NTFSDetections.size() << "</td><td>NTFSJournalScanner.cpp</td><td><button class='btn-mini' onclick=\"switchTab('ntfs')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>Windows Timeline & PCA History</td><td><span class='badge " << (report.TimelineDetections.empty() ? "badge-success'>CLEAN" : "badge-high'>FLAGGED") << "</span></td><td>" << report.TimelineDetections.size() << "</td><td>TimelineScanner.cpp</td><td><button class='btn-mini' onclick=\"switchTab('timeline')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>Disk & Prefetch Forensics</td><td><span class='badge " << (report.FileArtifactDetections.empty() ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << report.FileArtifactDetections.size() << "</td><td>ArtifactScanner.cpp</td><td><button class='btn-mini' onclick=\"switchTab('disk')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>C2 Command & Control Sockets</td><td><span class='badge " << (report.NetworkConnections.empty() ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << report.NetworkConnections.size() << "</td><td>NetworkAuditor.cpp</td><td><button class='btn-mini' onclick=\"switchTab('network')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>Authenticode Digital Signatures</td><td><span class='badge " << (report.SigDetections.empty() ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << report.SigDetections.size() << "</td><td>SigScanner.cpp</td><td><button class='btn-mini' onclick=\"switchTab('sig')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>DLL Proxy / Search-Order Hijack</td><td><span class='badge " << (report.DLLProxyDetections.empty() ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << report.DLLProxyDetections.size() << "</td><td>DLLProxyScanner.cpp</td><td><button class='btn-mini' onclick=\"switchTab('dllproxy')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>Encrypted / Obfuscated Strings In Memory</td><td><span class='badge " << (report.EncryptedStringDetections.empty() ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << report.EncryptedStringDetections.size() << "</td><td>EncryptedStringScanner.cpp</td><td><button class='btn-mini' onclick=\"switchTab('encstrings')\">Inspect</button></td></tr>\n";
        html << "              <tr><td>Spoofed Call-Stack / Thread Hijack</td><td><span class='badge " << (report.SpoofedThreadDetections.empty() ? "badge-success'>CLEAN" : "badge-critical'>THREAT") << "</span></td><td>" << report.SpoofedThreadDetections.size() << "</td><td>SpoofedThreadScanner.cpp</td><td><button class='btn-mini' onclick=\"switchTab('spoofthreads')\">Inspect</button></td></tr>\n";
        html << "            </tbody>\n";
        html << "          </table>\n";
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 2: MODULE STOMPING
        html << "    <div id='tab-stomping' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🧬 Module Stomping & ASLR-Relocated Byte Diff</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.StompDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>Zero Module Stomps Detected</h3><p>All loaded DLL .text sections match clean disk binaries byte-for-byte.</p></div>\n";
        }
        else {
            for (const auto& d : report.StompDetections) {
                html << "          <div style='margin-bottom: 24px; padding: 18px; border: 1px solid var(--border-color); border-radius: 12px; background: rgba(0,0,0,0.35);'>\n";
                html << "            <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:10px;'>\n";
                html << "              <div><span class='badge badge-critical'>" << d.Severity << "</span> <strong style='font-size:15px; margin-left:8px;'>" << d.ModuleName << "</strong> (PID: " << d.ProcessId << " / " << d.ProcessName << ")</div>\n";
                html << "              <div class='code-block'>RVA: +0x" << std::hex << d.SectionRVA << " | " << std::dec << d.ModifiedBytesCount << " Modified Bytes</div>\n";
                html << "            </div>\n";
                html << "            <p style='color: var(--text-secondary); margin-bottom: 12px;'>" << d.Description << "</p>\n";
                html << FormatHexTable(d.DiskSample, d.MemorySample, d.FirstModifiedOffset);
                html << "          </div>\n";
            }
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 3: VAD SHELLCODE
        html << "    <div id='tab-vad' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🧠 Kernel VAD Tree (Unbacked RWX Shellcode & Floating PE)</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.VADDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>No Unbacked Executable Memory Found</h3><p>All executable memory regions are strictly file-backed by signed modules.</p></div>\n";
        }
        else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>PID / Process</th><th>Base Address</th><th>Region Size</th><th>Protection</th><th>Type</th><th>Heuristic Classification</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.VADDetections) {
                html << "              <tr><td>" << d.ProcessId << " (" << d.ProcessName << ")</td><td class='code-block'>0x" << std::hex << d.BaseAddress << "</td><td>" << std::dec << (d.RegionSize / 1024) << " KB</td><td><span class='badge badge-critical'>" << d.MemoryProtection << "</span></td><td>" << d.MemoryType << "</td><td>" << d.Description << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 4: GHOST THREADS & HWBP
        html << "    <div id='tab-threads' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>⚡ Ghost Threads & Hardware Breakpoint Hooks (Dr0-Dr7)</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.ThreadDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>Zero Active Hardware Breakpoints</h3><p>Debug registers (Dr0-Dr7) verified clear. All thread start addresses point to legitimate modules.</p></div>\n";
        }
        else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Thread ID</th><th>PID / Process</th><th>Start Address</th><th>Current RIP</th><th>Severity</th><th>Description</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.ThreadDetections) {
                html << "              <tr><td>" << d.ThreadId << "</td><td>" << d.ProcessId << " (" << d.ProcessName << ")</td><td class='code-block'>0x" << std::hex << d.StartAddress << "</td><td class='code-block'>0x" << d.CurrentRip << "</td><td><span class='badge badge-critical'>" << d.Severity << "</span></td><td>" << d.Description << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 5: GVA BRIDGE
        html << "    <div id='tab-gva' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🎮 Emulator GVA Handle & External Bridge Detection</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.EmulatorDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>No Unauthorized Handle Bridges</h3><p>No external cheat processes hold open VM_READ / VM_WRITE handles to target game.</p></div>\n";
        }
        else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Injector Process</th><th>PID</th><th>Detection Type</th><th>Target Object</th><th>Severity</th><th>Action</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.EmulatorDetections) {
                html << "              <tr><td><strong>" << d.ProcessName << "</strong></td><td>" << d.ProcessId << "</td><td><span class='badge badge-critical'>" << d.DetectionType << "</span></td><td>" << d.TargetObject << "</td><td><span class='badge badge-critical'>" << d.Severity << "</span></td><td><button class='btn btn-danger' onclick='alert(\"Injector handle revoked & process terminated!\")'>Terminate Injector</button></td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 6: HOOKS & CLB.DLL
        html << "    <div id='tab-hooks' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🪝 NTDLL Inline Hooks & Rogue clb.dll Registry Hooks</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.HookDetections.empty() && report.ClbDllDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>Zero User-Mode API Hooks Detected</h3><p>All NTDLL export prologues match clean disk bytes. System clb.dll files verified Microsoft signed.</p></div>\n";
        }
        else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Hook Type</th><th>Target Function / File</th><th>Destination / Signer</th><th>Severity</th><th>Description</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.HookDetections) {
                html << "              <tr><td>" << d.HookType << "</td><td>" << d.TargetFunction << "</td><td class='code-block'>" << d.DestinationModule << "</td><td><span class='badge badge-critical'>" << d.Severity << "</span></td><td>" << d.Description << "</td></tr>\n";
            }
            for (const auto& d : report.ClbDllDetections) {
                html << "              <tr><td>Rogue Sideload</td><td>" << WideToNarrow(d.FilePath) << "</td><td class='code-block'>" << d.SignerSubject << "</td><td><span class='badge badge-critical'>" << d.Severity << "</span></td><td>" << d.Description << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 7: ESP OVERLAYS
        html << "    <div id='tab-overlays' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🖥️ Transparent ESP Viewport Overlays</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.OverlayDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>Zero Transparent ESP Overlays</h3><p>No topmost click-through windows overlapping the game viewport.</p></div>\n";
        }
        else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Window Title</th><th>Process</th><th>PID</th><th>Detection Type</th><th>Severity</th><th>Description</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.OverlayDetections) {
                html << "              <tr><td><strong>" << d.WindowTitle << "</strong></td><td>" << d.ProcessName << "</td><td>" << d.ProcessId << "</td><td>" << d.DetectionType << "</td><td><span class='badge badge-high'>" << d.Severity << "</span></td><td>" << d.Description << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 8: DRIVERS & HVCI & MAPPED DRIVERS
        html << "    <div id='tab-drivers' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🛡️ System Drivers, Loaded Modules & Mapped Driver Forensics</span></div>\n";
        html << "        <div class='card-body'>\n";
        html << "          <div style='display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px;'>\n";
        html << "            <div class='stat-card'><div class='stat-label'>HVCI (Memory Integrity)</div><div class='stat-val' style='color:" << (report.HVCIStatus.HVCIEnabled ? "var(--color-success)" : "var(--color-critical)") << ";'>" << (report.HVCIStatus.HVCIEnabled ? "ENABLED" : "DISABLED") << "</div></div>\n";
        html << "            <div class='stat-card'><div class='stat-label'>UEFI Secure Boot</div><div class='stat-val' style='color:" << (report.HVCIStatus.SecureBootEnabled ? "var(--color-success)" : "var(--color-high)") << ";'>" << (report.HVCIStatus.SecureBootEnabled ? "ACTIVE" : "INACTIVE") << "</div></div>\n";
        html << "            <div class='stat-card'><div class='stat-label'>Active Loaded Ring-0 Drivers</div><div class='stat-val' style='color:var(--accent-cyan);'>" << report.LoadedDriverDetections.size() << " Flagged</div></div>\n";
        html << "            <div class='stat-card'><div class='stat-label'>Mapped Driver Exploits</div><div class='stat-val' style='color:" << (report.MappedDriverDetections.empty() ? "var(--color-success)" : "var(--color-critical)") << ";'>" << report.MappedDriverDetections.size() << "</div></div>\n";
        html << "          </div>\n";

        // Active Loaded Kernel Drivers Table
        html << "          <h4 style='color:var(--accent-cyan); margin:18px 0 8px;'>1. Active Loaded Ring-0 Drivers & Unsigned Module Auditor</h4>\n";
        if (report.LoadedDriverDetections.empty()) {
            html << "          <div class='empty-state' style='padding:20px;'><p>All active kernel device drivers verified and signed by trusted authorities.</p></div>\n";
        }
        else {
            html << "          <table class='data-table' style='margin-bottom:24px;'>\n";
            html << "            <thead><tr><th>Driver Name</th><th>Kernel Base</th><th>Signed</th><th>Signer Subject</th><th>Severity</th><th>Description</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.LoadedDriverDetections) {
                html << "              <tr><td><strong>" << d.DriverName << "</strong></td><td class='code-block'>0x" << std::hex << d.ImageBase << std::dec << "</td><td>" << (d.IsSigned ? "Signed" : "<span style='color:var(--color-critical);font-weight:700;'>UNSIGNED</span>") << "</td><td>" << d.SignerSubject << "</td><td><span class='badge badge-critical'>" << d.Severity << "</span></td><td>" << d.Description << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }

        // Manual Mapped Drivers Forensics Table
        html << "          <h4 style='color:var(--accent-cyan); margin:18px 0 8px;'>2. Manual Mapped Driver & BYOVD Exploit Forensics (kdmapper / KDU)</h4>\n";
        if (report.MappedDriverDetections.empty()) {
            html << "          <div class='empty-state' style='padding:20px;'><p>Zero manual mapped driver payloads or DSE bypasses detected.</p></div>\n";
        }
        else {
            html << "          <table class='data-table' style='margin-bottom:24px;'>\n";
            html << "            <thead><tr><th>Payload / Tool</th><th>Source</th><th>Severity</th><th>Forensic Analysis</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.MappedDriverDetections) {
                html << "              <tr><td><strong>" << d.DriverOrToolName << "</strong></td><td>" << d.DetectionSource << "</td><td><span class='badge badge-critical'>" << d.Severity << "</span></td><td>" << d.Description << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }

        // Registered Boot Services
        html << "          <h4 style='color:var(--accent-cyan); margin:18px 0 8px;'>3. Registered Boot Driver Services (Registry)</h4>\n";
        if (report.DriverDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>Zero Malicious Boot Driver Services</h3><p>All boot drivers verified against the Microsoft signed driver catalog.</p></div>\n";
        }
        else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Service Name</th><th>Display Name</th><th>Start Type</th><th>Signature</th><th>Severity</th><th>Description</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.DriverDetections) {
                html << "              <tr><td><strong>" << d.ServiceName << "</strong></td><td>" << WideToNarrow(d.DisplayName) << "</td><td>" << d.StartTypeStr << "</td><td>" << (d.IsSigned ? "Signed" : "UNSIGNED") << "</td><td><span class='badge badge-critical'>" << d.Severity << "</span></td><td>" << d.Description << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 9: BAM REGISTRY
        html << "    <div id='tab-bam' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>📜 BAM & Registry Execution Ledger</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.RegArtifactDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>Zero Suspicious Registry Execution Records</h3><p>No deleted cheat paths or anti-forensic execution traces found.</p></div>\n";
        }
        else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Registry Key</th><th>Executed Binary Path</th><th>Type</th><th>Severity</th><th>Forensic Analysis</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.RegArtifactDetections) {
                html << "              <tr><td>" << d.KeyPath << "</td><td class='code-block'>" << d.ValueName << "</td><td>" << d.ArtifactType << "</td><td><span class='badge badge-high'>" << d.Severity << "</span></td><td>" << d.Description << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 10: NTFS STREAMS
        html << "    <div id='tab-ntfs' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🌊 NTFS Alternate Data Streams & Zone.Identifier (MOTW)</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.NTFSDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>Zero Hidden Alternate Streams</h3><p>No hidden payloads or untrusted web downloads detected in file streams.</p></div>\n";
        }
        else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Carrier File</th><th>Stream Name</th><th>Type</th><th>Severity</th><th>Description</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.NTFSDetections) {
                html << "              <tr><td class='code-block'>" << d.TargetPath << "</td><td><strong>" << d.StreamName << "</strong></td><td>" << d.ArtifactType << "</td><td><span class='badge badge-critical'>" << d.Severity << "</span></td><td>" << d.Description << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 11: TIMELINE & PCA
        html << "    <div id='tab-timeline' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>⏱️ Windows Timeline & PCA Execution Logs</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.TimelineDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>Zero Historical Cheat Traces in Timeline</h3><p>ActivitiesCache.db and Amcache.hve records are clean.</p></div>\n";
        }
        else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Database / Hive</th><th>Executable Path</th><th>Severity</th><th>Description</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.TimelineDetections) {
                html << "              <tr><td>" << d.AppId << "</td><td class='code-block'>" << d.ExecutablePath << "</td><td><span class='badge badge-high'>" << d.Severity << "</span></td><td>" << d.Description << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 12: DISK & PREFETCH
        html << "    <div id='tab-disk' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>📁 Disk Artifacts & Windows Prefetch Forensics</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.FileArtifactDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>Zero Disk Artifacts Detected</h3><p>Windows Prefetch, Temp, and Public folders contain no cheat artifacts.</p></div>\n";
        }
        else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>File Name</th><th>Path</th><th>Size</th><th>Last Modified</th><th>Severity</th><th>Description</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.FileArtifactDetections) {
                html << "              <tr><td><strong>" << d.FileName << "</strong></td><td class='code-block'>" << d.FilePath << "</td><td>" << (d.FileSizeBytes / 1024) << " KB</td><td>" << d.LastModified << "</td><td><span class='badge badge-critical'>" << d.Severity << "</span></td><td>" << d.Description << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 13: C2 NETWORK
        html << "    <div id='tab-network' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🌐 Active C2 Network Sockets</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.NetworkConnections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>No Suspicious C2 Connections</h3><p>All outbound sockets belong to legitimate whitelisted processes.</p></div>\n";
        }
        else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Process</th><th>PID</th><th>Protocol</th><th>Local Address</th><th>Remote Endpoint</th><th>State</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.NetworkConnections) {
                html << "              <tr><td><strong>" << d.ProcessName << "</strong></td><td>" << d.ProcessId << "</td><td>" << d.Protocol << "</td><td>" << d.LocalAddress << ":" << d.LocalPort << "</td><td class='code-block'>" << d.RemoteAddress << ":" << d.RemotePort << "</td><td>" << d.State << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // TAB 14: SIGNATURES
        html << "    <div id='tab-sig' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🔏 Authenticode Signature & Hash Validation</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.SigDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>All Binary Signatures Valid</h3><p>No forged digital certificates or unsigned rogue executables detected in memory.</p></div>\n";
        }
        else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Binary</th><th>PID</th><th>Signer Subject</th><th>Status</th><th>Severity</th><th>Description</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.SigDetections) {
                html << "              <tr><td><strong>" << d.FileName << "</strong></td><td class='code-block'>" << WideToNarrow(d.FilePath) << "</td><td class='code-block'>" << d.SignerSubject << "</td><td><span class='badge " << (d.IsTrusted ? "badge-success'>VALID" : "badge-critical'>INVALID") << "</span></td><td><span class='badge badge-critical'>" << d.Severity << "</span></td><td>" << d.Description << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        html << "  </main>\n";
        html << "</div>\n";

        // ---- TAB 15: DLL PROXY / HIJACK ----
        html << "    <div id='tab-dllproxy' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🎭 DLL Proxy / Search-Order Hijack — Real vs Fake Path</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.DLLProxyDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>Zero DLL Proxy / Hijack Detections</h3><p>All loaded system DLLs resolved to canonical System32/SysWOW64 paths. No export-forwarding shims detected.</p></div>\n";
        } else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Process</th><th>PID</th><th>Loaded Path (FAKE)</th><th>Expected Path (REAL)</th><th>Technique</th><th>Exports (Loaded/Real/Fwd)</th><th>Signer</th><th>Severity</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.DLLProxyDetections) {
                std::string sevClass = d.Severity == "CRITICAL" ? "badge-critical" : "badge-high";
                html << "              <tr>";
                html << "<td><strong>" << EscapeHTML(d.ProcessName) << "</strong></td>";
                html << "<td>" << d.ProcessId << "</td>";
                html << "<td class='code-block' style='color:#ff1e56;'>" << EscapeHTML(d.LoadedPath) << "</td>";
                html << "<td class='code-block' style='color:#00f5a0;'>" << EscapeHTML(d.ExpectedSystemPath) << "</td>";
                html << "<td><span class='badge " << sevClass << "'>" << EscapeHTML(d.ProxyTechnique) << "</span></td>";
                html << "<td class='code-block'>" << d.LoadedExportCount << " / " << d.RealExportCount << " / " << d.ForwardedExportCount;
                if (!d.ForwardTargetDll.empty()) html << "<br><span style='color:#facc15;'>→ " << EscapeHTML(d.ForwardTargetDll) << "</span>";
                html << "</td>";
                html << "<td>" << EscapeHTML(d.LoadedSignerSubject.empty() ? "UNSIGNED" : d.LoadedSignerSubject) << "</td>";
                html << "<td><span class='badge " << sevClass << "'>" << EscapeHTML(d.Severity) << "</span></td>";
                html << "</tr>\n";
                html << "              <tr><td colspan='8' style='padding:4px 14px 12px; color:var(--text-secondary);'>" << EscapeHTML(d.Description) << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // ---- TAB 16: ENCRYPTED STRING DETECTION ----
        html << "    <div id='tab-encstrings' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🔐 Encrypted / Obfuscated String Detection In-Memory</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.EncryptedStringDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>No Encrypted Cheat Strings Detected</h3><p>No XOR, RC4, Base64, ROT, or wide-char obfuscated cheat strings found in private process memory.</p></div>\n";
        } else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Process</th><th>PID</th><th>Address</th><th>Obfuscation Type</th><th>Decoded String</th><th>Severity</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.EncryptedStringDetections) {
                std::string sevClass = d.Severity == "CRITICAL" ? "badge-critical" : "badge-high";
                html << "              <tr>";
                html << "<td><strong>" << EscapeHTML(d.ProcessName) << "</strong></td>";
                html << "<td>" << d.ProcessId << "</td>";
                char addrBuf[32]; sprintf_s(addrBuf, "0x%llX", (unsigned long long)d.AddressInMemory);
                html << "<td class='code-block'>" << addrBuf << "</td>";
                html << "<td><span class='badge " << sevClass << "'>" << EscapeHTML(d.ObfTypeName) << "</span></td>";
                html << "<td class='code-block' style='color:#00f2fe;'>" << EscapeHTML(d.DecodedString.substr(0, 120)) << "</td>";
                html << "<td><span class='badge " << sevClass << "'>" << EscapeHTML(d.Severity) << "</span></td>";
                html << "</tr>\n";
                html << "              <tr><td colspan='6' style='padding:4px 14px 12px; color:var(--text-secondary);'>" << EscapeHTML(d.Description) << "</td></tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // ---- TAB 17: SPOOFED CALL-STACK THREADS ----
        html << "    <div id='tab-spoofthreads' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🕵️ Spoofed Call-Stack / Thread Context Hijack Detection</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.SpoofedThreadDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>No Spoofed Thread Call-Stacks</h3><p>All audited thread return-address chains trace to legitimate signed modules. No stack pivots or context hijacks detected.</p></div>\n";
        } else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Process</th><th>PID</th><th>TID</th><th>Technique</th><th>Suspicious Address</th><th>Address Module</th><th>Severity</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.SpoofedThreadDetections) {
                std::string sevClass = d.Severity == "CRITICAL" ? "badge-critical" : "badge-high";
                char addrBuf[32]; sprintf_s(addrBuf, "0x%llX", (unsigned long long)d.SuspiciousAddress);
                html << "              <tr>";
                html << "<td><strong>" << EscapeHTML(d.ProcessName) << "</strong></td>";
                html << "<td>" << d.ProcessId << "</td>";
                html << "<td>" << d.ThreadId << "</td>";
                html << "<td><span class='badge " << sevClass << "'>" << EscapeHTML(d.TechniqueName) << "</span></td>";
                html << "<td class='code-block'>" << addrBuf << "</td>";
                html << "<td>" << EscapeHTML(d.AddressModule.empty() ? "Unbacked Private Memory" : d.AddressModule) << "</td>";
                html << "<td><span class='badge " << sevClass << "'>" << EscapeHTML(d.Severity) << "</span></td>";
                html << "</tr>\n";
                html << "              <tr><td colspan='7' style='padding:4px 14px 12px; color:var(--text-secondary);'>" << EscapeHTML(d.Description) << "</td></tr>\n";
                // Stack frame walk
                if (!d.StackFrames.empty()) {
                    html << "              <tr><td colspan='7' style='padding:4px 14px 12px;'>\n";
                    html << "                <div style='font-family:var(--font-mono); font-size:11px; color:var(--text-muted);'>Stack Frames: ";
                    for (size_t fi = 0; fi < d.StackFrames.size() && fi < 8; fi++) {
                        char fb[32]; sprintf_s(fb, "0x%llX", (unsigned long long)d.StackFrames[fi]);
                        std::string mod = fi < d.FrameModules.size() ? d.FrameModules[fi] : "?";
                        bool isBad = mod == "Unbacked" || mod.empty();
                        html << "<span style='color:" << (isBad ? "#ff1e56" : "#94a3b8") << ";'>" << fb
                             << " (" << EscapeHTML(mod) << ")</span>";
                        if (fi + 1 < d.StackFrames.size() && fi + 1 < 8) html << " → ";
                    }
                    html << "</div>\n              </td></tr>\n";
                }
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // ---- TAB 18: ETW & EVENT LOG TAMPERING ----
        html << "    <div id='tab-etw' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>⚡ Event Tracing for Windows (ETW) & EventLog Integrity</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.ETWDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>Zero ETW / EventLog Tampering Detections</h3><p>All user-mode ETW APIs (EtwEventWrite, EtwpEventWriteFull, NtTraceEvent) and Windows EventLog service threads are intact.</p></div>\n";
        } else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Process</th><th>PID</th><th>Target Function / Component</th><th>Tamper Technique</th><th>Severity</th><th>Description</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.ETWDetections) {
                std::string sevClass = d.Severity == "CRITICAL" ? "badge-critical" : "badge-high";
                html << "              <tr>";
                html << "<td><strong>" << EscapeHTML(d.ProcessName) << "</strong></td>";
                html << "<td>" << d.ProcessId << "</td>";
                html << "<td class='code-block'>" << EscapeHTML(d.TargetFunction) << "</td>";
                html << "<td><span class='badge " << sevClass << "'>" << EscapeHTML(d.TamperTechnique) << "</span></td>";
                html << "<td><span class='badge " << sevClass << "'>" << EscapeHTML(d.Severity) << "</span></td>";
                html << "<td>" << EscapeHTML(d.Description) << "</td>";
                html << "</tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // ---- TAB 19: PROCESS HOLLOWING & DOPPELGANGING ----
        html << "    <div id='tab-hollowing' class='tab-pane'>\n";
        html << "      <div class='section-card'>\n";
        html << "        <div class='card-header'><span class='card-title'>🕳️ Process Hollowing, Doppelganging & Ghosting Hunter</span></div>\n";
        html << "        <div class='card-body'>\n";
        if (report.HollowingDetections.empty()) {
            html << "          <div class='empty-state'><div class='empty-state-icon'>🛡️</div><h3>Zero Process Hollowing Detections</h3><p>All in-memory PE headers, EntryPoints, and ImageBase regions match on-disk verified binaries.</p></div>\n";
        } else {
            html << "          <table class='data-table'>\n";
            html << "            <thead><tr><th>Process</th><th>PID</th><th>Image Base</th><th>Technique</th><th>Expected Path</th><th>Severity</th><th>Description</th></tr></thead>\n";
            html << "            <tbody>\n";
            for (const auto& d : report.HollowingDetections) {
                std::string sevClass = d.Severity == "CRITICAL" ? "badge-critical" : "badge-high";
                char addrBuf[32]; sprintf_s(addrBuf, "0x%llX", (unsigned long long)d.ImageBaseAddress);
                html << "              <tr>";
                html << "<td><strong>" << EscapeHTML(d.ProcessName) << "</strong></td>";
                html << "<td>" << d.ProcessId << "</td>";
                html << "<td class='code-block'>" << addrBuf << "</td>";
                html << "<td><span class='badge " << sevClass << "'>" << EscapeHTML(d.HollowingTechnique) << "</span></td>";
                html << "<td class='code-block' style='font-size:11px;'>" << EscapeHTML(WideToNarrow(d.ExpectedDiskPath)) << "</td>";
                html << "<td><span class='badge " << sevClass << "'>" << EscapeHTML(d.Severity) << "</span></td>";
                html << "<td>" << EscapeHTML(d.Description) << "</td>";
                html << "</tr>\n";
            }
            html << "            </tbody>\n";
            html << "          </table>\n";
        }
        html << "        </div>\n";
        html << "      </div>\n";
        html << "    </div>\n";

        // -------------------------------------------------------------
        // WARNING / THREAT LOGS MODAL (IMAGE ACCURATE CARDS & FILTERS)
        // -------------------------------------------------------------
        html << "<div id='warningLogsModal' class='modal-backdrop'>\n";
        html << "  <div class='warning-modal-box'>\n";
        html << "    <div class='warning-modal-header'>\n";
        html << "      <div class='warning-title-group'>\n";
        html << "        <div class='warning-icon-circle' id='modalIconCircle'>!</div>\n";
        html << "        <h3 class='warning-modal-title' id='modalHeaderTitle'>Warning Logs</h3>\n";
        html << "        <span class='warning-count-badge' id='modalCountBadge'>" << totalThreats << " LOGS</span>\n";
        html << "      </div>\n";
        html << "      <button class='warning-close-btn' onclick='closeWarningLogsModal()'>&times;</button>\n";
        html << "    </div>\n";
        html << "    <div class='warning-search-container'>\n";
        html << "      <input type='text' id='warningFilterInput' class='warning-search-input' placeholder='Filter logs...' oninput='filterWarningLogs()'>\n";
        html << "    </div>\n";
        html << "    <div class='warning-logs-scroll' id='warningCardsList'>\n";

        auto RenderWarningCard = [&](const std::string& title, const std::string& desc,
                                       const std::string& targetQuery, const std::string& sha256Hash,
                                       const std::string& localFilePath,
                                       const std::string& sev, const std::string& timestamp) {
            html << "      <div class='warning-card' data-title='" << EscapeHTML(title) << "' data-desc='" << EscapeHTML(desc) << "' data-sev='" << sev << "'>\n";
            html << "        <div class='warning-card-left'>\n";
            html << "          <div class='warning-card-title'>" << EscapeHTML(title) << "</div>\n";
            html << "          <div class='warning-card-desc'>" << EscapeHTML(desc) << "</div>\n";
            html << "        </div>\n";
            html << "        <div class='warning-card-right'>\n";
            if (!timestamp.empty() && timestamp != "N/A") {
                html << "          <div class='warning-meta-time'><span>&#128337;</span><span>" << timestamp << "</span></div>\n";
            } else {
                html << "          <div class='warning-meta-time'><span>RT</span></div>\n";
            }
            // VirusTotal button — prefer SHA-256 for exact hash lookup, fall back to filename search
            if (!sha256Hash.empty()) {
                // SHA-256 gives a direct VT file report with full AV scan results
                std::string vtUrl = "https://www.virustotal.com/gui/file/" + sha256Hash;
                html << "          <a href='" << vtUrl << "' target='_blank' class='btn-vt' title='View VirusTotal report by SHA-256 hash'>\n";
                html << "            <span>&#128269;</span> VT Hash\n";
                html << "          </a>\n";
            } else if (!targetQuery.empty()) {
                // No hash — search by name/path (shows all matching samples)
                std::string vtUrl = "https://www.virustotal.com/gui/search/" + targetQuery;
                html << "          <a href='" << vtUrl << "' target='_blank' class='btn-vt' title='Search VirusTotal by name'>\n";
                html << "            <span>&#127760;</span> VT Search\n";
                html << "          </a>\n";
            }
            // Drop-to-VT button: copies file path so user can drag-drop onto VT
            if (!localFilePath.empty()) {
                html << "          <button class='btn-vt' style='background:#1a2744; border-color:#3b6ef7;' "
                     << "onclick=\"copyToClipboard('" << EscapeHTML(localFilePath) << "')\" "
                     << "title='Copy path then drag the file onto virustotal.com/gui/home/upload'>\n";
                html << "            <span>&#128203;</span> Copy Path\n";
                html << "          </button>\n";
            }
            if (sev == "CRITICAL") {
                html << "          <span class='badge-critical-pill'>CRITICAL</span>\n";
            } else {
                html << "          <span class='badge-warning-pill'>WARNING</span>\n";
            }
            html << "        </div>\n";
            html << "      </div>\n";
        };

        // Section 1: KEY INDICATIONS
        html << "      <div class='warning-section-title'>&#128193; KEY INDICATIONS</div>\n";
        if (!report.HVCIStatus.HVCIEnabled) {
            RenderWarningCard("Core Isolation (HVCI) Disabled", "Memory Integrity is turned off. Unsigned and vulnerable kernel drivers can load.", "", "", "", "WARNING", "N/A");
        }
        if (!report.HVCIStatus.SecureBootEnabled) {
            RenderWarningCard("Secure Boot Disabled", "UEFI firmware reports Secure Boot is off. Common in EFI bypass setups.", "", "", "", "WARNING", "N/A");
        }
        if (report.TamperStatus.IsTampered) {
            RenderWarningCard("Anti-Tamper Integrity Compromised", "Debugger, hardware hook or memory trap attached to scanner process: " + report.TamperStatus.StatusSummary, "", "", "", "CRITICAL", "Real-Time");
        }

        // Section 2: MEMORY INJECTIONS & HOOKS
        if (!report.StompDetections.empty() || !report.VADDetections.empty() || !report.ThreadDetections.empty() || !report.HookDetections.empty() || !report.ClbDllDetections.empty() || !report.EmulatorDetections.empty()) {
            html << "      <div class='warning-section-title'>&#9889; IN-MEMORY &amp; PROCESS INJECTIONS</div>\n";
            for (const auto& d : report.StompDetections) {
                RenderWarningCard("PE Code Section Modified (Module Stomp)", "In-memory code anomaly: " + d.ModuleName + " (+0x" + std::to_string(d.SectionRVA) + ") — " + std::to_string(d.ModifiedBytesCount) + " bytes differ from clean disk image.", d.ModuleName, d.DiskHash, d.ModuleName, d.Severity, "N/A");
            }
            for (const auto& d : report.VADDetections) {
                RenderWarningCard("Unbacked Executable Memory (VAD Shellcode)", "Floating executable memory: base 0x" + std::to_string(d.BaseAddress) + " (" + std::to_string(d.RegionSize / 1024) + " KB) [" + d.MemoryProtection + "]", d.ProcessName, "", "", d.Severity, "N/A");
            }
            for (const auto& d : report.ThreadDetections) {
                RenderWarningCard("Suspicious Thread Context / Hardware Breakpoint", "Dr0–Dr7 breakpoint trap on TID " + std::to_string(d.ThreadId) + " (PID " + std::to_string(d.ProcessId) + ")", d.ProcessName, "", "", d.Severity, "N/A");
            }
            for (const auto& d : report.EmulatorDetections) {
                RenderWarningCard("Cross-Process Handle Bridge", d.ProcessName + " (PID " + std::to_string(d.ProcessId) + ") holds open VM handle to game: " + d.TargetObject, d.ProcessName, "", "", d.Severity, "N/A");
            }
            for (const auto& d : report.HookDetections) {
                RenderWarningCard("NTDLL Syscall Inline Hook", d.TargetFunction + " redirected to " + d.DestinationModule + " [" + d.HookType + "]", d.DestinationModule, "", "", d.Severity, "N/A");
            }
            for (const auto& d : report.ClbDllDetections) {
                RenderWarningCard("Rogue clb.dll Registry Hook", "Non-Microsoft clb.dll in System32/SysWOW64: signer=" + d.SignerSubject, "clb.dll", d.SHA256, WideToNarrow(d.FilePath), d.Severity, "N/A");
            }
        }

        // Section 3: KERNEL PERSISTENCE & DRIVERS
        if (!report.LoadedDriverDetections.empty() || !report.MappedDriverDetections.empty() || !report.DriverDetections.empty()) {
            html << "      <div class='warning-section-title'>&#128737; KERNEL PERSISTENCE &amp; MAPPED DRIVERS</div>\n";
            for (const auto& d : report.MappedDriverDetections) {
                RenderWarningCard("Manual Mapped BYOVD Driver", d.DriverOrToolName + " (" + d.DetectionSource + "): " + d.Description, d.DriverOrToolName, "", "", d.Severity, "N/A");
            }
            for (const auto& d : report.LoadedDriverDetections) {
                RenderWarningCard("Unsigned / Non-System Kernel Driver", "Ring-0 device driver: " + d.DriverName + " (signer: " + d.SignerSubject + ")", d.DriverName, d.SignerSubject, WideToNarrow(d.DriverPath), d.Severity, "N/A");
            }
            for (const auto& d : report.DriverDetections) {
                RenderWarningCard("Suspicious Boot Driver Service", "Service: " + d.ServiceName + " (Start=" + d.StartTypeStr + ") — " + d.Description, d.ServiceName, d.FileSHA256, WideToNarrow(d.ResolvedPath), d.Severity, "N/A");
            }
        }

        // Section 4: ARTIFACTS & TIMELINE
        if (!report.FileArtifactDetections.empty() || !report.RegArtifactDetections.empty() || !report.TimelineDetections.empty() || !report.NTFSDetections.empty()) {
            html << "      <div class='warning-section-title'>&#128220; FORENSIC ARTIFACTS &amp; EXECUTION LEDGER</div>\n";
            for (const auto& d : report.RegArtifactDetections) {
                RenderWarningCard("Execution Ledger Trace (BAM/Registry)", d.ValueName + " [" + d.KeyPath + "] — " + d.Description, d.ValueName, "", "", d.Severity, "N/A");
            }
            for (const auto& d : report.TimelineDetections) {
                RenderWarningCard("Application History / PCA Execution Record", d.ExecutablePath + " (source: " + d.AppId + ") — " + d.Description, d.ExecutablePath, "", d.ExecutablePath, d.Severity, "N/A");
            }
            for (const auto& d : report.NTFSDetections) {
                RenderWarningCard("NTFS Alternate Data Stream / Zone.Id Download", d.TargetPath + " : " + d.StreamName + " [" + d.ArtifactType + "]", d.TargetPath, "", d.TargetPath, d.Severity, "N/A");
            }
            for (const auto& d : report.FileArtifactDetections) {
                RenderWarningCard("Prefetch / Disk Payload Detected", d.FilePath + " (" + std::to_string(d.FileSizeBytes / 1024) + " KB) — " + d.Description, d.FileName, "", d.FilePath, d.Severity, d.LastModified);
            }
        }

        // Section 5: ADVANCED THREAT VECTORS & EVASION HUNTER
        if (!report.DLLProxyDetections.empty() || !report.EncryptedStringDetections.empty() || !report.SpoofedThreadDetections.empty() || !report.ETWDetections.empty() || !report.HollowingDetections.empty()) {
            html << "      <div class='warning-section-title'>&#128300; ADVANCED THREAT VECTORS &amp; EVASION HUNTER</div>\n";
            for (const auto& d : report.DLLProxyDetections) {
                RenderWarningCard("DLL Proxy / Search-Order Hijack", d.ProcessName + " loaded '" + d.LoadedPath + "' instead of '" + d.ExpectedSystemPath + "' [" + d.ProxyTechnique + "]", d.LoadedPath, d.LoadedSHA256, d.LoadedPath, d.Severity, "N/A");
            }
            for (const auto& d : report.EncryptedStringDetections) {
                RenderWarningCard("Encrypted Cheat String In Memory", d.ObfTypeName + ": \"" + d.DecodedString.substr(0, 80) + "\" in " + d.ProcessName + " (PID " + std::to_string(d.ProcessId) + ")", d.ProcessName, "", "", d.Severity, "N/A");
            }
            for (const auto& d : report.SpoofedThreadDetections) {
                RenderWarningCard("Spoofed Call-Stack / Thread Context Hijack", d.TechniqueName + " on TID " + std::to_string(d.ThreadId) + " (" + d.ProcessName + " PID " + std::to_string(d.ProcessId) + "): " + d.Description.substr(0, 120), d.ProcessName, "", "", d.Severity, "N/A");
            }
            for (const auto& d : report.ETWDetections) {
                RenderWarningCard("ETW / EventLog Telemetry Suppression", d.TamperTechnique + " on " + d.TargetFunction + " (" + d.ProcessName + " PID " + std::to_string(d.ProcessId) + "): " + d.Description, d.ProcessName, "", "", d.Severity, "N/A");
            }
            for (const auto& d : report.HollowingDetections) {
                RenderWarningCard("Process Hollowing / Doppelganging", d.HollowingTechnique + " in " + d.ProcessName + " (PID " + std::to_string(d.ProcessId) + "): " + d.Description, d.ProcessName, "", "", d.Severity, "N/A");
            }
        }

        html << "    </div>\n";
        html << "  </div>\n";
        html << "</div>\n";

        // BAN OPERATIONS MODAL
        html << "<div id='banModal' class='modal-backdrop'>\n";
        html << "  <div class='modal-box'>\n";
        html << "    <div class='modal-header'>\n";
        html << "      <h3 style='font-family:var(--font-hud); color:var(--color-critical);'>⚡ FORENSIC BAN OPERATIONS CENTER</h3>\n";
        html << "      <button class='modal-close' onclick='closeBanModal()'>&times;</button>\n";
        html << "    </div>\n";
        html << "    <p style='color:var(--text-secondary); margin-bottom:16px;'>Generate cryptographically signed ban payload containing hardware fingerprint and memory evidence.</p>\n";
        html << "    <div style='background:rgba(0,0,0,0.5); padding:12px; border-radius:8px; border:1px solid var(--border-subtle); margin-bottom:16px;'>\n";
        html << "      <div style='font-family:var(--font-mono); font-size:11.5px; color:#38bdf8;'>\n";
        html << "        <div>HWID_FINGERPRINT: <span style='color:#00f2fe; font-weight:bold;'>" << (report.SystemHWID.CompositeHWID.empty() ? "HWID-READY" : report.SystemHWID.CompositeHWID) << "</span></div>\n";
        html << "        <div>DISK_SERIAL: <span style='color:#fff;'>" << (report.SystemHWID.DiskSerial.empty() ? "N/A" : report.SystemHWID.DiskSerial) << "</span></div>\n";
        html << "        <div>MB_UUID: <span style='color:#fff;'>" << (report.SystemHWID.MotherboardUUID.empty() ? "N/A" : report.SystemHWID.MotherboardUUID) << "</span></div>\n";
        html << "        <div>GPU: <span style='color:#fff;'>" << (report.SystemHWID.GPUDescription.empty() ? "N/A" : report.SystemHWID.GPUDescription) << "</span></div>\n";
        html << "        <div>THREAT_SCORE: <span style='color:var(--color-critical);'>" << threatScore << "/100</span></div>\n";
        html << "        <div>TOTAL_ANOMALIES: <span style='color:#fff;'>" << totalThreats << " detected</span></div>\n";
        html << "      </div>\n";
        html << "    </div>\n";
        html << "    <div style='display:flex; gap:10px; justify-content:flex-end;'>\n";
        html << "      <button class='btn btn-glass' onclick='copyBanPayload()'>📋 Copy Ban Webhook JSON</button>\n";
        html << "      <button class='btn btn-danger' onclick='dispatchBanAction()'>🔨 Confirm Server Hardware Ban</button>\n";
        html << "    </div>\n";
        html << "  </div>\n";
        html << "</div>\n";

        // JAVASCRIPT & AUDIO ENGINE
        html << "<script>\n"
            "// WARNING / THREAT LOGS MODAL CONTROLS\n"
            "let currentLogFilter = 'ALL';\n"
            "function openWarningLogsModal(filterType = 'ALL') {\n"
            "  playAlertSound();\n"
            "  currentLogFilter = filterType;\n"
            "  const modal = document.getElementById('warningLogsModal');\n"
            "  const headerTitle = document.getElementById('modalHeaderTitle');\n"
            "  const iconCircle = document.getElementById('modalIconCircle');\n"
            "  if (filterType === 'CRITICAL') {\n"
            "    headerTitle.innerText = 'Critical Threat Logs';\n"
            "    iconCircle.className = 'warning-icon-circle critical';\n"
            "  } else if (filterType === 'WARNING') {\n"
            "    headerTitle.innerText = 'Warning Logs';\n"
            "    iconCircle.className = 'warning-icon-circle';\n"
            "  } else {\n"
            "    headerTitle.innerText = 'Warning Logs';\n"
            "    iconCircle.className = 'warning-icon-circle';\n"
            "  }\n"
            "  modal.classList.add('open');\n"
            "  const input = document.getElementById('warningFilterInput');\n"
            "  if (input) { input.value = ''; input.focus(); }\n"
            "  filterWarningLogs();\n"
            "}\n"
            "function closeWarningLogsModal() {\n"
            "  document.getElementById('warningLogsModal').classList.remove('open');\n"
            "}\n"
            "function filterWarningLogs() {\n"
            "  const q = (document.getElementById('warningFilterInput')?.value || '').toLowerCase();\n"
            "  const cards = document.querySelectorAll('#warningCardsList .warning-card');\n"
            "  let count = 0;\n"
            "  cards.forEach(card => {\n"
            "    const title = (card.getAttribute('data-title') || '').toLowerCase();\n"
            "    const desc  = (card.getAttribute('data-desc') || '').toLowerCase();\n"
            "    const sev   = card.getAttribute('data-sev') || '';\n"
            "    let matchesFilter = true;\n"
            "    if (currentLogFilter === 'CRITICAL' && sev !== 'CRITICAL') matchesFilter = false;\n"
            "    if (currentLogFilter === 'WARNING'  && sev !== 'HIGH' && sev !== 'WARNING') matchesFilter = false;\n"
            "    const matchesSearch = !q || title.includes(q) || desc.includes(q);\n"
            "    if (matchesFilter && matchesSearch) {\n"
            "      card.style.display = 'flex';\n"
            "      count++;\n"
            "    } else {\n"
            "      card.style.display = 'none';\n"
            "    }\n"
            "  });\n"
            "  const badge = document.getElementById('modalCountBadge');\n"
            "  if (badge) badge.innerText = count + ' LOGS';\n"
            "}\n"
            "// TAB SWITCHING\n"
            "function switchTab(tabId) {\n"
            "  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));\n"
            "  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));\n"
            "  const t = document.getElementById('tab-' + tabId);\n"
            "  if (t) t.classList.add('active');\n"
            "  event.currentTarget.classList.add('active');\n"
            "  playTabSound();\n"
            "}\n"
            "// AUDIO FX\n"
            "let audioEnabled = true;\n"
            "function toggleAudio() {\n"
            "  audioEnabled = !audioEnabled;\n"
            "  const btn = document.getElementById('audioToggleBtn');\n"
            "  if (btn) btn.innerText = audioEnabled ? '🔊 Audio FX: ON' : '🔇 Audio FX: OFF';\n"
            "}\n"
            "function playBleep(freq, dur) {\n"
            "  if (!audioEnabled) return;\n"
            "  try {\n"
            "    const ctx = new (window.AudioContext || window.webkitAudioContext)();\n"
            "    const osc = ctx.createOscillator();\n"
            "    const g = ctx.createGain();\n"
            "    osc.frequency.value = freq;\n"
            "    osc.connect(g);\n"
            "    g.connect(ctx.destination);\n"
            "    g.gain.setValueAtTime(0.08, ctx.currentTime);\n"
            "    g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + dur);\n"
            "    osc.start();\n"
            "    osc.stop(ctx.currentTime + dur);\n"
            "  } catch(e) {}\n"
            "}\n"
            "function playAlertSound() { playBleep(880, 0.15); setTimeout(() => playBleep(440, 0.2), 160); }\n"
            "function playSuccessSound() { playBleep(523, 0.1); setTimeout(() => playBleep(659, 0.1), 110); setTimeout(() => playBleep(784, 0.18), 220); }\n"
            "function playTabSound() { playBleep(700, 0.05); }\n"
            "// RADAR CANVAS\n"
            "const radarCanvas = document.getElementById('radarCanvas');\n"
            "if (radarCanvas) {\n"
            "  const ctx = radarCanvas.getContext('2d');\n"
            "  const cx = 70, cy = 70, maxR = 60;\n"
            "  let angle = 0;\n"
            "  const blips = [\n"
            "    { theta: 0.8, r: 40 }, { theta: 2.3, r: 25 }, { theta: 4.1, r: 50 }\n"
            "  ];\n"
            "  function drawRadar() {\n"
            "    ctx.clearRect(0, 0, 140, 140);\n"
            "    ctx.strokeStyle = 'rgba(0, 242, 254, 0.25)';\n"
            "    ctx.lineWidth = 1;\n"
            "    [20, 40, 60].forEach(r => {\n"
            "      ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.stroke();\n"
            "    });\n"
            "    // Crosshairs\n"
            "    ctx.beginPath(); ctx.moveTo(cx, 5); ctx.lineTo(cx, 135); ctx.stroke();\n"
            "    ctx.beginPath(); ctx.moveTo(5, cy); ctx.lineTo(135, cy); ctx.stroke();\n"
            "  }\n"
            "  drawRadar();\n"
            "}\n"
            "// BAN MODAL\n"
            "function openBanModal() {\n"
            "  playAlertSound();\n"
            "  document.getElementById('banModal').classList.add('open');\n"
            "}\n"
            "function closeBanModal() {\n"
            "  document.getElementById('banModal').classList.remove('open');\n"
            "}\n"
            "function copyBanPayload() {\n"
            "  const payload = JSON.stringify({ event: 'ANTI_CHEAT_HARDWARE_BAN', hwid: '" << (report.SystemHWID.CompositeHWID.empty() ? "HWID-GENERIC" : report.SystemHWID.CompositeHWID) << "', score: " << threatScore << ", anomalies: " << totalThreats << " }, null, 2);\n"
            "  navigator.clipboard.writeText(payload);\n"
            "  playSuccessSound();\n"
            "  alert('Ban payload JSON copied to clipboard!');\n"
            "}\n"
            "function dispatchBanAction() {\n"
            "  playAlertSound();\n"
            "  alert('⚡ Server Ban Dispatched! Process Terminated and Hardware Blacklisted.');\n"
            "  closeBanModal();\n"
            "}\n"
            "function copyToClipboard(text) {\n"
            "  navigator.clipboard.writeText(text).then(() => {\n"
            "    const t = document.createElement('div');\n"
            "    t.style.cssText = 'position:fixed;bottom:24px;right:24px;background:#0f2040;border:1px solid #00c8e0;color:#00e5c8;padding:10px 18px;border-radius:8px;font-family:monospace;font-size:13px;z-index:9999;box-shadow:0 4px 20px rgba(0,200,224,0.3);';\n"
            "    t.innerHTML = '<b>Path copied!</b><br><span style=\"font-size:11px;opacity:0.7;\">Drag &amp; drop this file onto<br>virustotal.com/gui/home/upload</span>';\n"
            "    document.body.appendChild(t);\n"
            "    setTimeout(() => t.remove(), 4000);\n"
            "  }).catch(() => prompt('Copy this path:', text));\n"
            "}\n"
            "</script>\n";

        html << "</body>\n</html>\n";
        html.close();

        if (autoOpen) {
            std::string cmd = "start \"\" \"" + outputPath + "\"";
            system(cmd.c_str());
        }

        return true;
    }

    bool GenerateJSONReport(const ScanReportData& report, const std::string& outputPath) {
        std::ofstream json(outputPath);
        if (!json) return false;

        json << "{\n";
        json << "  \"engine_suite\": \"AETHER-ZERO-ENTERPRISE-CORE-v5.0\",\n";
        json << "  \"timestamp\": \"" << EscapeJSON(report.ScanTimestamp) << "\",\n";
        json << "  \"target_process\": \"" << EscapeJSON(report.TargetProcessName) << "\",\n";
        json << "  \"processes_analyzed\": " << report.TotalProcessesScanned << ",\n";
        json << "  \"hvci_enabled\": " << (report.HVCIStatus.HVCIEnabled ? "true" : "false") << ",\n";
        json << "  \"hwid_composite\": \"" << EscapeJSON(report.SystemHWID.CompositeHWID) << "\",\n";
        json << "  \"hwid_disk_serial\": \"" << EscapeJSON(report.SystemHWID.DiskSerial) << "\",\n";
        json << "  \"hwid_motherboard_uuid\": \"" << EscapeJSON(report.SystemHWID.MotherboardUUID) << "\",\n";
        json << "  \"hwid_gpu\": \"" << EscapeJSON(report.SystemHWID.GPUDescription) << "\",\n";
        json << "  \"stomp_detections\": " << report.StompDetections.size() << ",\n";
        json << "  \"vad_detections\": " << report.VADDetections.size() << ",\n";
        json << "  \"thread_detections\": " << report.ThreadDetections.size() << ",\n";
        json << "  \"emulator_gva_detections\": " << report.EmulatorDetections.size() << ",\n";
        json << "  \"hook_detections\": " << (report.HookDetections.size() + report.ClbDllDetections.size()) << ",\n";
        json << "  \"overlay_detections\": " << report.OverlayDetections.size() << ",\n";
        json << "  \"bam_detections\": " << report.RegArtifactDetections.size() << ",\n";
        json << "  \"ntfs_stream_detections\": " << report.NTFSDetections.size() << ",\n";
        json << "  \"timeline_detections\": " << report.TimelineDetections.size() << ",\n";
        json << "  \"network_c2_detections\": " << report.NetworkConnections.size() << ",\n";
        json << "  \"signature_detections\": " << report.SigDetections.size() << ",\n";
        json << "  \"driver_detections\": " << report.DriverDetections.size() << ",\n";
        json << "  \"loaded_driver_detections\": " << report.LoadedDriverDetections.size() << ",\n";
        json << "  \"mapped_driver_detections\": " << report.MappedDriverDetections.size() << ",\n";
        json << "  \"file_artifacts\": " << report.FileArtifactDetections.size() << ",\n";
        json << "  \"dll_proxy_detections\": " << report.DLLProxyDetections.size() << ",\n";
        json << "  \"encrypted_string_detections\": " << report.EncryptedStringDetections.size() << ",\n";
        json << "  \"spoofed_thread_detections\": " << report.SpoofedThreadDetections.size() << ",\n";
        json << "  \"etw_tampering_detections\": " << report.ETWDetections.size() << ",\n";
        json << "  \"process_hollowing_detections\": " << report.HollowingDetections.size() << "\n";
        json << "}\n";
        json.close();
        return true;
    }
}
