// ntfs_raw.c — Raw NTFS volume access + boot sector parsing
#include "common.h"

BOOL ParseNtfsBoot(HANDLE hVolume, NTFS_CONTEXT* ctx) {
    BYTE bootSector[512] = {0};
    DWORD bytesRead = 0;

    // Read first sector (boot sector)
    LARGE_INTEGER li;
    li.QuadPart = 0;
    if (!SetFilePointerEx(hVolume, li, NULL, FILE_BEGIN)) return FALSE;
    if (!ReadFile(hVolume, bootSector, sizeof(bootSector), &bytesRead, NULL))
        return FALSE;

    NTFS_BOOT_SECTOR* boot = (NTFS_BOOT_SECTOR*)bootSector;

    // Validate
    if (boot->signature != 0xAA55) {
        wprintf(L"      [ERR] Invalid boot signature: 0x%04X\n", boot->signature);
        return FALSE;
    }
    if (memcmp(boot->oemId, "NTFS    ", 8) != 0) {
        wprintf(L"      [ERR] Not NTFS: %.8s\n", boot->oemId);
        return FALSE;
    }

    ctx->bytesPerSector    = boot->bytesPerSector;
    ctx->sectorsPerCluster = boot->sectorsPerCluster;
    ctx->clusterSize       = ctx->bytesPerSector * ctx->sectorsPerCluster;
    ctx->mftStartCluster   = boot->mftStartCluster;
    ctx->totalClusters     = boot->totalSectors / ctx->sectorsPerCluster;

    // MFT record size
    BYTE clustersPerMftRecord = boot->clustersPerMftRecord;
    if (clustersPerMftRecord > 0) {
        ctx->mftRecordSize = ctx->clusterSize * clustersPerMftRecord;
    } else {
        // Negative = 2^(-n) bytes
        ctx->mftRecordSize = 1 << ((-clustersPerMftRecord) & 0xFF);
    }

    // Validate
    if (ctx->mftRecordSize < 256 || ctx->mftRecordSize > 4096) {
        ctx->mftRecordSize = 1024; // Default
    }

    return TRUE;
}
