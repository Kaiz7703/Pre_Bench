// hive_extractor.c — File extraction via raw NTFS traversal
// Walks MFT directory tree ($INDEX_ROOT + $INDEX_ALLOCATION INDX records)
// to find and extract target files
#include "common.h"

// ─── Read clusters from volume ───
static BOOL ReadClusters(HANDLE hVolume, NTFS_CONTEXT* ctx,
    DWORD64 startCluster, DWORD count, PBYTE buffer) {
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)startCluster * ctx->clusterSize;
    if (!SetFilePointerEx(hVolume, li, NULL, FILE_BEGIN)) return FALSE;

    DWORD bytesRead;
    DWORD toRead = count * ctx->clusterSize;
    return ReadFile(hVolume, buffer, toRead, &bytesRead, NULL) && bytesRead == toRead;
}

// ─── Scan a run of INDEX_ENTRY structures for a child name ───
// Works for both $INDEX_ROOT (entries after the 16-byte header) and INDX
// records (entries after the 0x18-byte record header; the first entry in an
// INDX record is a name-less subnode stub which never matches).
static BOOL ScanIndexEntries(PBYTE entries, DWORD bytes,
    PWSTR childName, DWORD64* childRecord) {
    PBYTE p = entries, end = entries + bytes;
    while (p + sizeof(INDEX_ENTRY) <= end) {
        INDEX_ENTRY* e = (INDEX_ENTRY*)p;
        if (e->entryLength < sizeof(INDEX_ENTRY)) break;

        if (!(e->flags & 0x02) && e->fileNameAttrLength >= 66) {
            FILE_NAME_ATTR* fn = (FILE_NAME_ATTR*)(p + sizeof(INDEX_ENTRY));
            if (fn->nameLength > 0) {
                WCHAR entryName[256] = {0};
                memcpy(entryName, fn->name,
                    min((DWORD)fn->nameLength * 2, sizeof(entryName) - 2));

                if (_wcsicmp(entryName, childName) == 0) {
                    *childRecord = e->mftReference & 0x0000FFFFFFFFFFFFULL;
                    return TRUE;
                }
            }
        }

        if (e->flags & 0x02) break; // INDEX_ENTRY_END
        p += e->entryLength;
    }
    return FALSE;
}

// ─── Apply update-sequence fixups to an INDX record ───
static void ApplyIndxFixups(PBYTE record, USHORT fixupOffset,
    USHORT fixupCount, DWORD sectorSize) {
    PBYTE arr = record + fixupOffset;
    for (USHORT i = 1; i < fixupCount; i++) {
        DWORD pos = i * sectorSize - 2;
        if (pos + 2 <= fixupOffset + (DWORD)fixupCount * 2) {
            memcpy(record + pos, arr + i * 2, 2);
        }
    }
}

// ─── Scan $INDEX_ALLOCATION (non-resident) INDX records for a child name ───
static BOOL ScanIndexAllocation(HANDLE hVolume, NTFS_CONTEXT* ntfs,
    PBYTE dirRec, PWSTR childName, DWORD64* childRecord, DWORD blockSize) {
    PBYTE attrPtr = dirRec + ((MFT_FILE_RECORD*)dirRec)->firstAttrOffset;
    while (*(PDWORD)attrPtr != 0xFFFFFFFF && *(PDWORD)attrPtr != 0) {
        ATTR_HEADER* hdr = (ATTR_HEADER*)attrPtr;

        if (hdr->type == 0xA0 /* $INDEX_ALLOCATION */ && hdr->nonResident) {
            ATTR_NONRESIDENT* nonRes = (ATTR_NONRESIDENT*)attrPtr;
            DWORD64 totalSize = nonRes->realSize;
            if (totalSize == 0 || totalSize > 512 * 1024 * 1024) { attrPtr += hdr->length; continue; }

            PBYTE buf = (PBYTE)VirtualAlloc(NULL, (SIZE_T)totalSize,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buf) { attrPtr += hdr->length; continue; }

            // Decode DataRuns
            PBYTE drPtr = (PBYTE)attrPtr + nonRes->dataRunOffset;
            ULONG64 currentCluster = 0, offset = 0;

            while (*drPtr != 0x00 && offset < totalSize) {
                BYTE header = *drPtr++;
                BYTE lenSize = header & 0x0F;
                BYTE offSize = (header >> 4) & 0x0F;

                ULONG64 runLength = 0;
                for (int i = 0; i < lenSize; i++)
                    runLength |= ((ULONG64)(*drPtr++)) << (i * 8);

                LONGLONG runOffset = 0;
                for (int i = 0; i < offSize; i++)
                    runOffset |= ((ULONG64)(*drPtr++)) << (i * 8);
                if (offSize > 0 && (runOffset & (1LL << ((offSize * 8) - 1)))) {
                    LONGLONG signMask = 0;
                    for (int i = offSize * 8; i < 64; i++) signMask |= (1LL << i);
                    runOffset |= signMask;
                }

                currentCluster += runOffset;
                DWORD64 runBytes = runLength * ntfs->clusterSize;
                if (offset + runBytes > totalSize) runBytes = totalSize - offset;

                if (runBytes > 0 && currentCluster > 0) {
                    ReadClusters(hVolume, ntfs, currentCluster,
                        (DWORD)((runBytes + ntfs->clusterSize - 1) / ntfs->clusterSize),
                        buf + offset);
                }
                offset += runBytes;
            }

            // Walk INDX records (each starts with "INDX" signature)
            DWORD recSize = blockSize ? blockSize : 4096;
            for (DWORD64 off = 0; off + 0x40 <= totalSize; off += recSize) {
                PBYTE indx = buf + off;
                if (memcmp(indx, "INDX", 4) != 0) continue;
                USHORT fixupOff = *(PUSHORT)(indx + 4);
                USHORT fixupCnt = *(PUSHORT)(indx + 6);
                if (fixupCnt < 1 || fixupCnt > 32 ||
                    fixupOff + (DWORD)fixupCnt * 2 > recSize) continue;

                ApplyIndxFixups(indx, fixupOff, fixupCnt, ntfs->bytesPerSector);

                // Index node header @0x18: entries offset (relative to 0x18),
                // total entry bytes @0x1C. Typical: entries at 0x18+0x28 = 0x40.
                DWORD entriesOff = *(PDWORD)(indx + 0x18);
                DWORD entriesBytes = *(PDWORD)(indx + 0x1C);
                if (entriesOff < 0x10 ||
                    0x18 + entriesOff + entriesBytes > recSize) continue;

                if (ScanIndexEntries(indx + 0x18 + entriesOff, entriesBytes,
                    childName, childRecord)) {
                    VirtualFree(buf, 0, MEM_RELEASE);
                    return TRUE;
                }
            }
            VirtualFree(buf, 0, MEM_RELEASE);
        }
        attrPtr += hdr->length;
    }
    return FALSE;
}

// ─── Find child entry in directory by name ───
BOOL FindChildInDir(HANDLE hVolume, NTFS_CONTEXT* ntfs,
    PBYTE mftBuffer, SIZE_T mftSize, DWORD64 dirRecordNum,
    PWSTR childName, DWORD64* childRecord) {

    DWORD recSize = ntfs->mftRecordSize;
    if (recSize < 256 || recSize > 4096) recSize = 1024;
    if ((SIZE_T)dirRecordNum * recSize + recSize > mftSize) return FALSE;

    PBYTE dirRec = mftBuffer + dirRecordNum * recSize;
    if (memcmp(((MFT_FILE_RECORD*)dirRec)->signature, "FILE", 4) != 0)
        return FALSE;

    MFT_FILE_RECORD* fileRec = (MFT_FILE_RECORD*)dirRec;
    if (!(fileRec->flags & 0x0002)) return FALSE; // Not a directory

    DWORD indexBlockSize = 4096;

    // Walk attributes: $INDEX_ROOT (0x90) first, then $INDEX_ALLOCATION (0xA0)
    PBYTE attrPtr = dirRec + fileRec->firstAttrOffset;
    while (*(PDWORD)attrPtr != 0xFFFFFFFF && *(PDWORD)attrPtr != 0) {
        ATTR_HEADER* attrHdr = (ATTR_HEADER*)attrPtr;

        if (attrHdr->type == ATTR_INDEX_ROOT && !attrHdr->nonResident) {
            ATTR_RESIDENT* resAttr = (ATTR_RESIDENT*)attrPtr;
            PBYTE indexRoot = (PBYTE)attrPtr + resAttr->valueOffset;
            if (resAttr->valueLength >= 16 + sizeof(INDEX_ENTRY)) {
                // index root header: type(4) + collation(4) + indexBlockSize(4) +
                //                    clustersPerIndexRec(1) + reserved(3)
                indexBlockSize = *(PDWORD)(indexRoot + 8);
                if (ScanIndexEntries(indexRoot + 16, resAttr->valueLength - 16,
                    childName, childRecord))
                    return TRUE;
            }
        }
        attrPtr += attrHdr->length;
    }

    // Not in $INDEX_ROOT — large directories keep children in INDX records
    return ScanIndexAllocation(hVolume, ntfs, dirRec, childName, childRecord, indexBlockSize);
}

// ─── Extract file data from NTFS by path ───
BOOL ExtractFileFromNtfs(HANDLE hVolume, NTFS_CONTEXT* ntfs,
    PBYTE mftBuffer, SIZE_T mftSize, PWSTR filePath, HIVE_DATA* hive) {

    DWORD recSize = ntfs->mftRecordSize;
    if (recSize < 256 || recSize > 4096) recSize = 1024;

    // Start from root directory (MFT record #5)
    DWORD64 currentRecord = 5;
    DWORD64 childRecord = 0;

    // Make a mutable copy of the path for tokenization
    WCHAR pathCopy[MAX_PATH];
    wcscpy_s(pathCopy, MAX_PATH, filePath);

    // Split by backslash
    WCHAR* token = NULL;
    WCHAR* context = NULL;

    // Skip leading backslash if present
    if (pathCopy[0] == L'\\') {
        token = wcstok_s(pathCopy + 1, L"\\", &context);
    } else {
        token = wcstok_s(pathCopy, L"\\", &context);
    }

    while (token != NULL) {
        if (!FindChildInDir(hVolume, ntfs, mftBuffer, mftSize,
            currentRecord, token, &childRecord)) {
            return FALSE;
        }
        currentRecord = childRecord;
        token = wcstok_s(NULL, L"\\", &context);
    }

    // Now currentRecord points to the target file's MFT record
    if ((SIZE_T)currentRecord * recSize + recSize > mftSize) return FALSE;
    PBYTE fileRec = mftBuffer + currentRecord * recSize;
    if (memcmp(((MFT_FILE_RECORD*)fileRec)->signature, "FILE", 4) != 0)
        return FALSE;

    // Walk attributes to find $DATA
    PBYTE attrPtr = fileRec + ((MFT_FILE_RECORD*)fileRec)->firstAttrOffset;
    while (*(PDWORD)attrPtr != 0xFFFFFFFF && *(PDWORD)attrPtr != 0) {
        ATTR_HEADER* attrHdr = (ATTR_HEADER*)attrPtr;

        if (attrHdr->type == ATTR_DATA) {
            if (!attrHdr->nonResident) {
                // Resident data — copy directly
                ATTR_RESIDENT* resAttr = (ATTR_RESIDENT*)attrPtr;
                hive->size = resAttr->valueLength;
                hive->data = (PBYTE)VirtualAlloc(NULL, max(hive->size, 1),
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (hive->data) {
                    memcpy(hive->data,
                        (PBYTE)attrPtr + resAttr->valueOffset,
                        hive->size);
                }
                return TRUE;
            } else {
                // Non-resident data — extract via DataRuns
                ATTR_NONRESIDENT* nonRes = (ATTR_NONRESIDENT*)attrPtr;
                hive->size = (SIZE_T)nonRes->realSize;

                // Read DataRuns
                PBYTE drPtr = (PBYTE)attrPtr + nonRes->dataRunOffset;

                // VirtualAlloc for sector-aligned buffer (required by FILE_FLAG_NO_BUFFERING)
                hive->data = (PBYTE)VirtualAlloc(NULL, hive->size,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!hive->data) return FALSE;

                SIZE_T bytesRead = 0;
                ULONG64 currentCluster = 0;

                while (*drPtr != 0x00 && bytesRead < hive->size) {
                    BYTE header = *drPtr++;
                    BYTE lenSize = header & 0x0F;
                    BYTE offSize = (header >> 4) & 0x0F;

                    // Read length
                    ULONG64 runLength = 0;
                    for (int i = 0; i < lenSize; i++)
                        runLength |= ((ULONG64)(*drPtr++)) << (i * 8);

                    // Read offset (signed)
                    LONGLONG runOffset = 0;
                    for (int i = 0; i < offSize; i++)
                        runOffset |= ((ULONG64)(*drPtr++)) << (i * 8);
                    if (offSize > 0 && (runOffset & (1LL << ((offSize * 8) - 1)))) {
                        LONGLONG signMask = 0;
                        for (int i = offSize * 8; i < 64; i++) signMask |= (1LL << i);
                        runOffset |= signMask;
                    }

                    currentCluster += runOffset;

                    SIZE_T runBytes = (SIZE_T)(runLength * ntfs->clusterSize);
                    if (bytesRead + runBytes > hive->size)
                        runBytes = hive->size - bytesRead;

                    if (runBytes > 0 && currentCluster > 0) {
                        ReadClusters(hVolume, ntfs, currentCluster,
                            (DWORD)((runBytes + ntfs->clusterSize - 1) / ntfs->clusterSize),
                            hive->data + bytesRead);
                    }

                    bytesRead += runBytes;
                }

                return bytesRead > 0;
            }
        }

        attrPtr += attrHdr->length;
    }

    return FALSE;
}
