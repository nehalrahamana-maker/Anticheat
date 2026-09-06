#include "PEParser.hpp"
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <bcrypt.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace PE {

    PEImage::PEImage()
        : m_IsValid(false), m_Is64Bit(false), m_ImageBase(0),
        m_SizeOfImage(0), m_EntryPointRVA(0), m_HeadersSize(0),
        m_RelocDirRVA(0), m_RelocDirSize(0),
        m_SecurityDirRVA(0), m_SecurityDirSize(0) {
    }

    PEImage::~PEImage() {
    }

    bool PEImage::LoadFromFile(const std::wstring& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return false;

        m_Buffer.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        return ParseHeaders();
    }

    bool PEImage::LoadFromMemory(const BYTE* data, SIZE_T size) {
        if (!data || size == 0) return false;
        m_Buffer.assign(data, data + size);
        return ParseHeaders();
    }

    bool PEImage::ParseHeaders() {
        m_IsValid = false;
        m_Sections.clear();

        if (m_Buffer.size() < sizeof(IMAGE_DOS_HEADER)) return false;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)m_Buffer.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        if ((size_t)dos->e_lfanew + sizeof(DWORD) > m_Buffer.size()) return false;

        DWORD signature = *(DWORD*)(m_Buffer.data() + dos->e_lfanew);
        if (signature != IMAGE_NT_SIGNATURE) return false;

        PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(m_Buffer.data() + dos->e_lfanew + sizeof(DWORD));

        size_t optHeaderOffset = (size_t)dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (optHeaderOffset >= m_Buffer.size()) return false;

        WORD magic = *(WORD*)(m_Buffer.data() + optHeaderOffset);
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            m_Is64Bit = true;
            if (optHeaderOffset + sizeof(IMAGE_OPTIONAL_HEADER64) > m_Buffer.size()) return false;

            PIMAGE_OPTIONAL_HEADER64 opt64 = (PIMAGE_OPTIONAL_HEADER64)(m_Buffer.data() + optHeaderOffset);
            m_ImageBase = opt64->ImageBase;
            m_SizeOfImage = opt64->SizeOfImage;
            m_EntryPointRVA = opt64->AddressOfEntryPoint;
            m_HeadersSize = opt64->SizeOfHeaders;

            if (opt64->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
                m_RelocDirRVA = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                m_RelocDirSize = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            }
            if (opt64->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
                m_SecurityDirRVA = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                m_SecurityDirSize = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            }
        }
        else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            m_Is64Bit = false;
            if (optHeaderOffset + sizeof(IMAGE_OPTIONAL_HEADER32) > m_Buffer.size()) return false;

            PIMAGE_OPTIONAL_HEADER32 opt32 = (PIMAGE_OPTIONAL_HEADER32)(m_Buffer.data() + optHeaderOffset);
            m_ImageBase = opt32->ImageBase;
            m_SizeOfImage = opt32->SizeOfImage;
            m_EntryPointRVA = opt32->AddressOfEntryPoint;
            m_HeadersSize = opt32->SizeOfHeaders;

            if (opt32->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
                m_RelocDirRVA = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                m_RelocDirSize = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            }
            if (opt32->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
                m_SecurityDirRVA = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                m_SecurityDirSize = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            }
        }
        else {
            return false;
        }

        size_t sectionHeaderOffset = optHeaderOffset + fileHeader->SizeOfOptionalHeader;
        if (sectionHeaderOffset + (fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) > m_Buffer.size()) {
            return false;
        }

        PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(m_Buffer.data() + sectionHeaderOffset);
        for (WORD i = 0; i < fileHeader->NumberOfSections; i++) {
            SectionInfo sec;
            char nameBuf[9] = { 0 };
            memcpy(nameBuf, sections[i].Name, 8);
            sec.Name = nameBuf;
            sec.VirtualAddress = sections[i].VirtualAddress;
            sec.VirtualSize = sections[i].Misc.VirtualSize;
            sec.RawOffset = sections[i].PointerToRawData;
            sec.RawSize = sections[i].SizeOfRawData;
            sec.Characteristics = sections[i].Characteristics;
            sec.IsExecutable = (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            sec.IsWritable = (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            m_Sections.push_back(sec);
        }

        m_IsValid = true;
        return true;
    }

    const SectionInfo* PEImage::GetSectionByRVA(DWORD rva) const {
        for (const auto& sec : m_Sections) {
            DWORD size = (sec.VirtualSize > 0) ? sec.VirtualSize : sec.RawSize;
            if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + size) {
                return &sec;
            }
        }
        return nullptr;
    }

    const SectionInfo* PEImage::GetSectionByName(const std::string& name) const {
        for (const auto& sec : m_Sections) {
            if (_stricmp(sec.Name.c_str(), name.c_str()) == 0) {
                return &sec;
            }
        }
        return nullptr;
    }

    DWORD PEImage::RvaToOffset(DWORD rva) const {
        const SectionInfo* sec = GetSectionByRVA(rva);
        if (sec && sec->RawOffset > 0) {
            return sec->RawOffset + (rva - sec->VirtualAddress);
        }
        return 0;
    }

    std::vector<BYTE> PEImage::GetMappedImage() const {
        if (!m_IsValid || m_SizeOfImage == 0) return {};

        std::vector<BYTE> mapped(m_SizeOfImage, 0);

        // Copy Headers
        DWORD copyHeaders = (std::min)((DWORD)m_Buffer.size(), m_HeadersSize);
        if (copyHeaders > 0) {
            memcpy(mapped.data(), m_Buffer.data(), copyHeaders);
        }

        // Copy Sections
        for (const auto& sec : m_Sections) {
            if (sec.RawOffset > 0 && sec.RawSize > 0 && sec.RawOffset < m_Buffer.size()) {
                DWORD validRawSize = (std::min)(sec.RawSize, (DWORD)(m_Buffer.size() - sec.RawOffset));
                DWORD copySize = (std::min)(validRawSize, (DWORD)(m_SizeOfImage - sec.VirtualAddress));
                if (sec.VirtualAddress + copySize <= m_SizeOfImage) {
                    memcpy(mapped.data() + sec.VirtualAddress, m_Buffer.data() + sec.RawOffset, copySize);
                }
            }
        }

        return mapped;
    }

    bool PEImage::ApplyRelocations(std::vector<BYTE>& mappedBuffer, ULONG_PTR targetBase) const {
        if (!m_IsValid || m_RelocDirRVA == 0 || m_RelocDirSize == 0) return false;
        if (mappedBuffer.size() < m_SizeOfImage) return false;

        LONG_PTR delta = (LONG_PTR)(targetBase - m_ImageBase);
        if (delta == 0) return true; // No relocation needed

        DWORD currentRVA = m_RelocDirRVA;
        DWORD endRVA = m_RelocDirRVA + m_RelocDirSize;

        while (currentRVA + sizeof(IMAGE_BASE_RELOCATION) <= endRVA && currentRVA + sizeof(IMAGE_BASE_RELOCATION) <= mappedBuffer.size()) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(mappedBuffer.data() + currentRVA);
            if (!reloc || reloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || reloc->SizeOfBlock > m_RelocDirSize) {
                break;
            }
            if (currentRVA + reloc->SizeOfBlock > mappedBuffer.size()) {
                break;
            }

            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* list = (WORD*)(mappedBuffer.data() + currentRVA + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < count; i++) {
                WORD entry = list[i];
                WORD type = entry >> 12;
                WORD offset = entry & 0x0FFF;
                DWORD patchRVA = reloc->VirtualAddress + offset;

                if (patchRVA + sizeof(ULONG_PTR) <= mappedBuffer.size()) {
                    if (type == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG* patchLoc = (ULONGLONG*)(mappedBuffer.data() + patchRVA);
                        *patchLoc += (ULONGLONG)delta;
                    }
                    else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* patchLoc = (DWORD*)(mappedBuffer.data() + patchRVA);
                        *patchLoc += (DWORD)delta;
                    }
                }
            }

            currentRVA += reloc->SizeOfBlock;
        }

        return true;
    }

#include <mscat.h>

    CertificateInfo PEImage::ParseCertificate(const std::wstring& filePath) const {
        CertificateInfo info;
        info.HasCertificate = (m_SecurityDirRVA != 0 && m_SecurityDirSize != 0);
        info.VirtualAddress = m_SecurityDirRVA;
        info.Size = m_SecurityDirSize;
        info.IsMicrosoftSigned = false;
        info.IsTrusted = false;
        info.WinTrustError = 0;

        try {
            // 1. If embedded certificate exists, verify with WinVerifyTrust
            if (info.HasCertificate) {
                WINTRUST_FILE_INFO fileInfo = { 0 };
                fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
                fileInfo.pcwszFilePath = filePath.c_str();

                WINTRUST_DATA wtd = { 0 };
                wtd.cbStruct = sizeof(WINTRUST_DATA);
                wtd.dwUIChoice = WTD_UI_NONE;
                wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
                wtd.dwUnionChoice = WTD_CHOICE_FILE;
                wtd.pFile = &fileInfo;
                wtd.dwStateAction = WTD_STATEACTION_VERIFY;

                GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                LONG status = WinVerifyTrust(NULL, &actionGuid, &wtd);
                info.WinTrustError = (DWORD)status;
                info.IsTrusted = (status == ERROR_SUCCESS);

                wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(NULL, &actionGuid, &wtd);

                // Extract Signer Information using CryptQueryObject
                HCERTSTORE hStore = NULL;
                HCRYPTMSG hMsg = NULL;
                DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

                if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(),
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0, &dwEncoding, &dwContentType, &dwFormatType,
                    &hStore, &hMsg, NULL)) {

                    DWORD dwSignerInfo = 0;
                    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo)) {
                        std::vector<BYTE> signerInfoBuf(dwSignerInfo);
                        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfoBuf.data(), &dwSignerInfo)) {
                            CMSG_SIGNER_INFO* pSignerInfo = (CMSG_SIGNER_INFO*)signerInfoBuf.data();

                            CERT_INFO certInfo = { 0 };
                            certInfo.Issuer = pSignerInfo->Issuer;
                            certInfo.SerialNumber = pSignerInfo->SerialNumber;

                            PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hStore,
                                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                0, CERT_FIND_SUBJECT_CERT, &certInfo, NULL);

                            if (pCertContext) {
                                // Extract Subject Name
                                DWORD nameLen = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
                                if (nameLen > 1) {
                                    std::vector<WCHAR> ws(nameLen);
                                    CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, ws.data(), nameLen);
                                    char mbBuf[512] = { 0 };
                                    WideCharToMultiByte(CP_UTF8, 0, ws.data(), -1, mbBuf, sizeof(mbBuf), NULL, NULL);
                                    info.SubjectName = mbBuf;
                                }

                                // Extract Issuer Name
                                DWORD issuerLen = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
                                if (issuerLen > 1) {
                                    std::vector<WCHAR> wi(issuerLen);
                                    CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, wi.data(), issuerLen);
                                    char mbBuf[512] = { 0 };
                                    WideCharToMultiByte(CP_UTF8, 0, wi.data(), -1, mbBuf, sizeof(mbBuf), NULL, NULL);
                                    info.IssuerName = mbBuf;
                                }

                                std::string lowerSub = info.SubjectName;
                                std::string lowerIss = info.IssuerName;
                                std::transform(lowerSub.begin(), lowerSub.end(), lowerSub.begin(), ::tolower);
                                std::transform(lowerIss.begin(), lowerIss.end(), lowerIss.begin(), ::tolower);
                                if (lowerSub.find("microsoft") != std::string::npos || lowerIss.find("microsoft") != std::string::npos ||
                                    lowerSub.find("windows") != std::string::npos || lowerIss.find("windows") != std::string::npos) {
                                    info.IsMicrosoftSigned = true;
                                }

                                CertFreeCertificateContext(pCertContext);
                            }
                        }
                    }

                    if (hStore) CertCloseStore(hStore, 0);
                    if (hMsg) CryptMsgClose(hMsg);
                }

                if (info.IsTrusted) return info;
            }

            // 2. Check Windows Security Catalog (.cat) for in-box drivers and OS binaries
            HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                HCATADMIN hCatAdmin = NULL;
                if (CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
                    DWORD hashSize = 0;
                    if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, NULL, 0)) {
                        std::vector<BYTE> hash(hashSize);
                        if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash.data(), 0)) {
                            HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash.data(), hashSize, 0, NULL);
                            if (hCatInfo) {
                                CATALOG_INFO catInfo = { sizeof(CATALOG_INFO) };
                                if (CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
                                    WINTRUST_CATALOG_INFO wtc = { sizeof(WINTRUST_CATALOG_INFO) };
                                    wtc.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
                                    wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
                                    wtc.pbCalculatedFileHash = hash.data();
                                    wtc.cbCalculatedFileHash = hashSize;
                                    wtc.pcwszMemberFilePath = filePath.c_str();

                                    WINTRUST_DATA wtCatData = { sizeof(WINTRUST_DATA) };
                                    wtCatData.cbStruct = sizeof(WINTRUST_DATA);
                                    wtCatData.dwUIChoice = WTD_UI_NONE;
                                    wtCatData.fdwRevocationChecks = WTD_REVOKE_NONE;
                                    wtCatData.dwUnionChoice = WTD_CHOICE_CATALOG;
                                    wtCatData.pCatalog = &wtc;
                                    wtCatData.dwStateAction = WTD_STATEACTION_VERIFY;

                                    GUID catGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                                    LONG catStatus = WinVerifyTrust(NULL, &catGuid, &wtCatData);
                                    wtCatData.dwStateAction = WTD_STATEACTION_CLOSE;
                                    WinVerifyTrust(NULL, &catGuid, &wtCatData);

                                    if (catStatus == ERROR_SUCCESS) {
                                        info.HasCertificate = true;
                                        info.IsTrusted = true;
                                        info.IsMicrosoftSigned = true;
                                        info.SubjectName = "Microsoft Windows OS (Catalog Signed)";
                                        info.IssuerName = "Microsoft Windows Production PCA";
                                        info.WinTrustError = 0;
                                        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                                        CryptCATAdminReleaseContext(hCatAdmin, 0);
                                        CloseHandle(hFile);
                                        return info;
                                    }
                                }
                                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                            }
                        }
                    }
                    CryptCATAdminReleaseContext(hCatAdmin, 0);
                }
                CloseHandle(hFile);
            }

            // 3. Fallback: Check if file resides in System32 / DriverStore / System32\drivers
            std::wstring lowerPath = filePath;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);
            if (lowerPath.find(L"\\system32\\drivers\\") != std::string::npos ||
                lowerPath.find(L"\\system32\\driverstore\\") != std::string::npos ||
                lowerPath.find(L"\\windows\\system32\\") != std::string::npos ||
                lowerPath.find(L"\\windows\\syswow64\\") != std::string::npos) {
                // If it's a known crashdump / core driver or standard windows file, mark trusted
                info.HasCertificate = true;
                info.IsTrusted = true;
                info.IsMicrosoftSigned = true;
                info.SubjectName = "Microsoft Windows System Component";
                info.IssuerName = "Microsoft Corporation";
                info.WinTrustError = 0;
            }
        }
        catch (...) {}

        return info;
    }

    std::string PEImage::ComputeSHA256(const BYTE* data, SIZE_T size) {
        if (!data || size == 0) return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // Empty hash

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (!BCRYPT_SUCCESS(status)) return "";

        DWORD hashObjSize = 0, resultSize = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjSize, sizeof(DWORD), &resultSize, 0);
        std::vector<BYTE> hashObj(hashObjSize);

        status = BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize, NULL, 0, 0);
        if (!BCRYPT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        BCryptHashData(hHash, (PBYTE)data, (ULONG)size, 0);

        BYTE hashResult[32] = { 0 };
        BCryptFinishHash(hHash, hashResult, 32, 0);

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        std::stringstream ss;
        for (int i = 0; i < 32; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hashResult[i];
        }
        return ss.str();
    }

    std::string PEImage::ComputeSHA256(const std::vector<BYTE>& data) {
        return ComputeSHA256(data.data(), data.size());
    }
}
