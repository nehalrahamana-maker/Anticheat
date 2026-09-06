#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

namespace PE {

    struct SectionInfo {
        std::string Name;
        DWORD VirtualAddress;
        DWORD VirtualSize;
        DWORD RawOffset;
        DWORD RawSize;
        DWORD Characteristics;
        bool IsExecutable;
        bool IsWritable;
    };

    struct CertificateInfo {
        bool HasCertificate;
        DWORD VirtualAddress;
        DWORD Size;
        std::string SubjectName;
        std::string IssuerName;
        std::string SerialNumber;
        bool IsMicrosoftSigned;
        bool IsTrusted;
        DWORD WinTrustError;
    };

    class PEImage {
    public:
        PEImage();
        ~PEImage();

        bool LoadFromFile(const std::wstring& filePath);
        bool LoadFromMemory(const BYTE* data, SIZE_T size);

        bool IsValid() const { return m_IsValid; }
        bool Is64Bit() const { return m_Is64Bit; }
        ULONG_PTR GetImageBase() const { return m_ImageBase; }
        DWORD GetSizeOfImage() const { return m_SizeOfImage; }
        DWORD GetEntryPointRVA() const { return m_EntryPointRVA; }
        const std::vector<SectionInfo>& GetSections() const { return m_Sections; }
        const std::vector<BYTE>& GetRawBuffer() const { return m_Buffer; }

        // Find section by RVA or Name
        const SectionInfo* GetSectionByRVA(DWORD rva) const;
        const SectionInfo* GetSectionByName(const std::string& name) const;

        // Convert RVA to File Offset
        DWORD RvaToOffset(DWORD rva) const;

        // Get a mapped virtual image of the PE (as it would appear in memory)
        std::vector<BYTE> GetMappedImage() const;

        // Apply base relocations to a mapped image buffer for a specific target base address
        bool ApplyRelocations(std::vector<BYTE>& mappedBuffer, ULONG_PTR targetBase) const;

        // Parse and verify digital signature (Authenticode)
        CertificateInfo ParseCertificate(const std::wstring& filePath) const;

        // Compute SHA-256 hash of a byte buffer
        static std::string ComputeSHA256(const BYTE* data, SIZE_T size);
        static std::string ComputeSHA256(const std::vector<BYTE>& data);

    private:
        bool ParseHeaders();

        std::vector<BYTE> m_Buffer;
        bool m_IsValid;
        bool m_Is64Bit;
        ULONG_PTR m_ImageBase;
        DWORD m_SizeOfImage;
        DWORD m_EntryPointRVA;
        DWORD m_HeadersSize;
        std::vector<SectionInfo> m_Sections;
        DWORD m_RelocDirRVA;
        DWORD m_RelocDirSize;
        DWORD m_SecurityDirRVA;
        DWORD m_SecurityDirSize;
    };

}
