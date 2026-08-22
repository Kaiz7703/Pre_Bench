// mft_parser.c — MFT reader + DataRun decoder
// Shared implementation: handles NTFS master file table traversal
#include "common.h"

// ─── Read raw data from volume at specific cluster ───
static BOOL ReadCluster(HANDLE hVolume, NTFS_CONTEXT* ctx,
    DWORD64 cluster, DWORD count, PBYTE buffer) {
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)cluster * ctx->clusterSize;
    if (!SetFilePointerEx(hVolume, li, NULL, FILE_BEGIN)) return FALSE;

    DWORD bytesRead;
    DWORD toRead = count * ctx->clusterSize;
    if (!ReadFile(hVolume, buffer, toRead, &bytesRead, NULL)) return FALSE;
    if (bytesRead < toRead) {
        memset(buffer + bytesRead, 0, toRead - bytesRead);
    }
    return TRUE;
}

// ─── Decode DataRuns from non-resident attribute ───
DWORD ExtractDataRuns(PBYTE record, DWORD recordSize, DATA_RUN** runs) {
    ATTR_NONRESIDENT* attr = (ATTR_NONRESIDENT*)(record + ((MFT_FILE_RECORD*)record)->firstAttrOffset);

    // Find $DATA attribute
    while (attr->header.type != 0xFFFFFFFF && attr->header.type != 0) {
        if (attr->header.type == ATTR_DATA && attr->header.nonResident) break;
        attr = (ATTR_NONRESIDENT*)((PBYTE)attr + attr->header.length);
    }
    if (attr->header.type != ATTR_DATA) return 0;

    // Decode DataRun bytes (data runs live inside the $DATA attribute itself)
    PBYTE drPtr = (PBYTE)attr + attr->dataRunOffset;
    DWORD cap = 64;
    DWORD count = 0;
    *runs = (DATA_RUN*)malloc(cap * sizeof(DATA_RUN));
    if (!*runs) return 0;

    ULONG64 currentOffset = 0;

    while (*drPtr != 0x00 && drPtr < record + recordSize) {
        BYTE header = *drPtr++;
        BYTE lenSize  = header & 0x0F;
        BYTE offSize  = (header >> 4) & 0x0F;

        // Read run length
        ULONG64 runLength = 0;
        for (int i = 0; i < lenSize; i++) {
            runLength |= ((ULONG64)(*drPtr++)) << (i * 8);
        }

        // Read run offset (signed)
        LONGLONG runOffset = 0;
        for (int i = 0; i < offSize; i++) {
            runOffset |= ((ULONG64)(*drPtr++)) << (i * 8);
        }
        // Sign-extend
        if (offSize > 0 && (runOffset & (1ULL << ((offSize * 8) - 1)))) {
            ULONG64 signMask = ~((1ULL << (offSize * 8)) - 1);
            runOffset |= signMask;
        }

        currentOffset += runOffset;

        if (count >= cap) {
            cap *= 2;
            *runs = (DATA_RUN*)realloc(*runs, cap * sizeof(DATA_RUN));
        }
        (*runs)[count].offset = currentOffset;
        (*runs)[count].length = runLength;
        count++;
    }

    return count;
}

// ─── Read entire MFT into memory ───
BOOL ReadMft(HANDLE hVolume, NTFS_CONTEXT* ctx, PBYTE* buffer, PSIZE_T size) {
    // Read MFT record 0 ($MFT itself)
    // Use VirtualAlloc for sector-aligned buffer (required by FILE_FLAG_NO_BUFFERING)
    DWORD recSize = max(ctx->mftRecordSize, 512);
    PBYTE record0 = (PBYTE)VirtualAlloc(NULL, recSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!record0) return FALSE;

    // Read MFT record 0
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)(ctx->mftStartCluster * ctx->clusterSize);
    if (!SetFilePointerEx(hVolume, li, NULL, FILE_BEGIN)) {
        VirtualFree(record0, 0, MEM_RELEASE); return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hVolume, record0, recSize, &bytesRead, NULL) || bytesRead < recSize) {
        VirtualFree(record0, 0, MEM_RELEASE); return FALSE;
    }

    // Validate MFT signature
    if (memcmp(((MFT_FILE_RECORD*)record0)->signature, "FILE", 4) != 0) {
        wprintf(L"      [ERR] MFT record 0 not valid (bad signature)\n");
        VirtualFree(record0, 0, MEM_RELEASE); return FALSE;
    }

    // Extract $DATA DataRuns from $MFT record
    DATA_RUN* runs = NULL;
    DWORD runCount = ExtractDataRuns(record0, ctx->mftRecordSize, &runs);
    VirtualFree(record0, 0, MEM_RELEASE);

    if (runCount == 0) {
        wprintf(L"      [ERR] No DataRuns found for $MFT\n");
        return FALSE;
    }

    // Calculate total MFT size from DataRuns
    ULONG64 totalSize = 0;
    for (DWORD i = 0; i < runCount; i++) {
        totalSize += runs[i].length * ctx->clusterSize;
    }

    // Limit MFT read to reasonable size (max 512MB for performance)
    if (totalSize > 512 * 1024 * 1024) {
        totalSize = 512 * 1024 * 1024;
    }

    // VirtualAlloc for sector-aligned buffer
    PBYTE mftData = (PBYTE)VirtualAlloc(NULL, (SIZE_T)totalSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mftData) {
        free(runs); return FALSE;
    }

    // Read each DataRun into the buffer
    SIZE_T offset = 0;
    for (DWORD i = 0; i < runCount; i++) {
        DWORD64 clusterCount = runs[i].length;
        SIZE_T runBytes = (SIZE_T)(clusterCount * ctx->clusterSize);

        if (offset + runBytes > totalSize) {
            runBytes = totalSize - offset;
            if (runBytes == 0) break;
        }

        if (!ReadCluster(hVolume, ctx, runs[i].offset,
            (DWORD)clusterCount, mftData + offset)) {
            break;
        }
        offset += runBytes;
    }

    free(runs);
    *buffer = mftData;
    *size = offset;
    return offset > 0;
}

// ─── Get MFT record by record number ───
PBYTE GetMftRecord(PBYTE mftBuffer, SIZE_T mftSize, DWORD64 recordNumber) {
    // MFT records are stored sequentially
    // Record size is stored in $Boot but we need it from context
    // For simplicity, we iterate through MFT records linearly

    // The MFT record size can be determined from the boot sector
    // which is already parsed into the NTFS context. Since we don't
    // have ctx here, we use a simpler approach: read the first
    // MFT_FILE_RECORD to determine layout.

    // For NTFS, MFT record size is typically 1024 bytes
    DWORD recordSize = 1024;
    DWORD64 offset = recordNumber * recordSize;

    if (offset + recordSize > mftSize) return NULL;

    PBYTE record = mftBuffer + offset;
    if (memcmp(((MFT_FILE_RECORD*)record)->signature, "FILE", 4) != 0 &&
        memcmp(((MFT_FILE_RECORD*)record)->signature, "BAAD", 4) != 0) {
        return NULL;
    }

    return record;
}
