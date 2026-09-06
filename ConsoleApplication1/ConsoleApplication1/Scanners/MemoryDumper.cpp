#include "MemoryDumper.hpp"
#include "SyscallEngine.hpp"
#include <fstream>
#include <vector>

namespace MemoryDumper {

    DumpResult DumpMemoryRegion(DWORD pid, ULONG_PTR baseAddress, SIZE_T sizeBytes, const std::string& outputFile) {
        DumpResult res;

        if (sizeBytes == 0 || sizeBytes > (100 * 1024 * 1024)) { // 100 MB safety limit
            res.ErrorMessage = "Invalid region size requested.";
            return res;
        }

        HANDLE hProc = NULL;
        OBJECT_ATTRIBUTES_EX objAttr = { sizeof(OBJECT_ATTRIBUTES_EX) };
        CLIENT_ID_EX cid = { (HANDLE)(ULONG_PTR)pid, NULL };

        NTSTATUS st = SyscallEngine::DirectNtOpenProcess(
            &hProc,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            &objAttr,
            &cid
        );

        if (!NT_SUCCESS(st) || !hProc) {
            res.ErrorMessage = "Failed to open target process with VM_READ.";
            return res;
        }

        std::vector<BYTE> buffer(sizeBytes, 0);
        SIZE_T bytesRead = 0;

        NTSTATUS readSt = SyscallEngine::DirectNtReadVirtualMemory(
            hProc,
            (PVOID)baseAddress,
            buffer.data(),
            sizeBytes,
            &bytesRead
        );

        CloseHandle(hProc);

        if (!NT_SUCCESS(readSt) || bytesRead == 0) {
            res.ErrorMessage = "Failed to read virtual memory pages from target.";
            return res;
        }

        std::ofstream out(outputFile, std::ios::binary);
        if (!out.is_open()) {
            res.ErrorMessage = "Failed to open destination dump file on disk.";
            return res;
        }

        out.write(reinterpret_cast<const char*>(buffer.data()), bytesRead);
        out.close();

        res.Success = true;
        res.SavedFilePath = outputFile;
        res.BytesDumped = bytesRead;
        return res;
    }
}
