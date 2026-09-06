#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace NTFSJournalScanner {

    struct NTFSArtifactDetection {
        std::string TargetPath;
        std::string StreamName;    // e.g. Zone.Identifier, hidden payload stream
        std::string ArtifactType;  // ALTERNATE_DATA_STREAM, REPLACED_FILE_TRACE, DELETED_JOURNAL_RECORD
        std::string Severity;      // CRITICAL, HIGH
        std::string Description;
    };

    // Scans for Alternate Data Streams (Zone.Identifier/MOTW) and NTFS file replacement/deletion artifacts
    std::vector<NTFSArtifactDetection> ScanNTFSArtifacts();
}
