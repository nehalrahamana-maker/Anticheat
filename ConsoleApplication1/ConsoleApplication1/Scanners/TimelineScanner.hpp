#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace TimelineScanner {

    struct TimelineDetection {
        std::string AppId;
        std::string ExecutablePath;
        std::string ArtifactType; // TIMELINE_ACTIVITIES_CACHE, PCA_SVC_LOG, DIAGTRACK_EXECUTION
        std::string LastActiveTime;
        std::string Severity;     // CRITICAL, HIGH
        std::string Description;
    };

    // Scans Windows ConnectedDevicesPlatform ActivitiesCache and PCA logs for deleted execution records
    std::vector<TimelineDetection> ScanTimelineActivities();
}
