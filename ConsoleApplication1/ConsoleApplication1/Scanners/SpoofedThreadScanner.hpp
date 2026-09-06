#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace SpoofedThreadScanner {

    // The specific call-stack / thread spoofing technique detected
    enum class SpoofTechnique {
        RETURN_ADDRESS_SPOOF,       // Return address on stack points to gadget/shellcode, not legit module
        FAKE_STACK_FRAME,           // Stack frame built with forged RBP/RSP chain pointing into legit DLL
        THREAD_CONTEXT_HIJACK,      // Thread context (RIP/RSP) was forcibly set via SetThreadContext
        CALL_STACK_HEAP_TRAMPOLINES,// Chain of heap-allocated trampolines used as return path
        FIBER_HIDDEN_EXECUTION,     // Fiber object used to hide execution outside normal thread list
        STACK_PIVOT,                // RSP redirected to non-stack region (ROP pivot gadget)
    };

    struct SpoofedThreadDetection {
        DWORD       ProcessId   = 0;
        std::string ProcessName;
        DWORD       ThreadId    = 0;

        SpoofTechnique  Technique;
        std::string     TechniqueName;  // Human-readable

        ULONG_PTR   SuspiciousAddress = 0; // The address that triggered detection
        std::string AddressModule;          // What module (or "Unbacked") backs that address

        // Stack walk information (up to 8 frames)
        std::vector<ULONG_PTR> StackFrames;
        std::vector<std::string> FrameModules;

        std::string Severity;    // "CRITICAL" or "HIGH"
        std::string Description;
    };

    // Inspect all threads in a process for call-stack / context spoofing
    std::vector<SpoofedThreadDetection> ScanProcessSpoofedThreads(DWORD pid, const std::string& procName);

    // Scan all running processes
    std::vector<SpoofedThreadDetection> ScanAllProcessesSpoofedThreads();

} // namespace SpoofedThreadScanner
