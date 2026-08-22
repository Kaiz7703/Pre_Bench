// hive_extractor.c — File extraction via raw NTFS traversal
// Walks MFT directory tree ($INDEX_ROOT + $INDEX_ALLOCATION INDX records)
// to find and extract target files
#include "common.h"

static int g_dbg = 0;
void NtfsSetDebug(int on) { g_dbg = on; }

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

// ─── Apply USA fixups (MFT records and INDX records) ───
// On disk the last 2 bytes of every sector hold the update-sequence number;
// the true bytes are in the fixup array at usaOff. Without this, any field
// straddling a sector boundary decodes as garbage.
static void ApplyUsaFixups(PBYTE rec, DWORD recSize, USHORT usaOff,
    USHORT usaCnt, DWORD sectorSize) {
    if (usaCnt < 1 || usaCnt > 32 || sectorSize < 512) return;
    if (usaOff + (DWORD)usaCnt * 2 > recSize) return;
    PBYTE arr = rec + usaOff;
    for (USHORT i = 1; i < usaCnt; i++) {
        DWORD pos = i * sectorSize - 2;
        if (pos + 2 <= recSize) memcpy(rec + pos, arr + i * 2, 2);
    }
}

// ─── Scan a run of INDEX_ENTRY structures for a child name ───
// Works for both $INDEX_ROOT (entries after the 16-byte header) and INDX
// records (entries after the 0x18-byte record header; the first entry in an
// INDX record is a name-less subnode stub which never matches).
static BOOL ScanIndexEntries(PBYTE entries, DWORD bytes,
    PWSTR childName, DWORD64* childRecord) {
    PBYTE p = entries, end = entries + bytes;
    int dbgCount = 0;
    while (p + sizeof(INDEX_ENTRY) <= end) {
        INDEX_ENTRY* e = (INDEX_ENTRY*)p;
        if (e->entryLength < sizeof(INDEX_ENTRY)) break;

        if (g_dbg && dbgCount++ < 32) {
            wprintf(L"      [entry] len=%u keylen=%u flags=0x%02X",
                e->entryLength, e->fileNameAttrLength, e->flags);
            if (!(e->flags & 0x02) && e->fileNameAttrLength >= 66) {
                FILE_NAME_ATTR* fn = (FILE_NAME_ATTR*)(p + sizeof(INDEX_ENTRY));
                if (fn->nameLength > 0 && fn->nameLength <= 255) {
                    WCHAR dbgName[48];
                    DWORD n = min((DWORD)fn->nameLength, 47);
                    memcpy(dbgName, fn->name, n * sizeof(WCHAR));
                    dbgName[n] = 0;
                    wprintf(L" name=%ls", dbgName);
                }
            }
            wprintf(L"\n");
        }

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

            DWORD recSize = blockSize ? blockSize : 4096;
            if (recSize < 512 || recSize > 65536) recSize = 4096;
            if (g_dbg) wprintf(L"    [idxalloc] realSize=%llu blockSize=%u\n", totalSize, recSize);

            // +recSize slack: the last run may be rounded up to whole clusters
            PBYTE buf = (PBYTE)VirtualAlloc(NULL, (SIZE_T)(totalSize + recSize),
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
                if (offSize > 0 && offSize < 8 &&
                    (runOffset & (1LL << (offSize * 8 - 1)))) {
                    runOffset |= ~((1LL << (offSize * 8)) - 1);
                }

                currentCluster += runOffset;
                DWORD64 runBytes = runLength * ntfs->clusterSize;
                if (offset + runBytes > totalSize) runBytes = totalSize - offset;

                if (runBytes > 0 && currentCluster > 0) {
                    DWORD cl = (DWORD)((runBytes + ntfs->clusterSize - 1) / ntfs->clusterSize);
                    if (g_dbg) wprintf(L"    [idxalloc] run: lcn=%llu clusters=%u\n", currentCluster, cl);
                    ReadClusters(hVolume, ntfs, currentCluster, cl, buf + offset);
                }
                offset += runBytes;
            }

            // Walk INDX records (each starts with "INDX" signature)
            for (DWORD64 off = 0; off + 0x40 <= totalSize; off += recSize) {
                PBYTE indx = buf + off;
                if (memcmp(indx, "INDX", 4) != 0) {
                    if (g_dbg) wprintf(L"    [indx @%llu] bad sig %02X %02X %02X %02X\n",
                        off, indx[0], indx[1], indx[2], indx[3]);
                    continue;
                }
                USHORT fixupOff = *(PUSHORT)(indx + 4);
                USHORT fixupCnt = *(PUSHORT)(indx + 6);
                if (fixupCnt < 1 || fixupCnt > 32 ||
                    fixupOff + (DWORD)fixupCnt * 2 > recSize) continue;

                ApplyUsaFixups(indx, recSize, fixupOff, fixupCnt, ntfs->bytesPerSector);

                // Index node header @0x18: entries offset (relative to 0x18),
                // total entry bytes @0x1C. Typical: entries at 0x18+0x28 = 0x40.
                DWORD entriesOff = *(PDWORD)(indx + 0x18);
                DWORD entriesBytes = *(PDWORD)(indx + 0x1C);
                if (g_dbg) wprintf(L"    [indx @%llu] fixup=%u/%u entriesOff=0x%X entriesBytes=%u\n",
                    off, fixupOff, fixupCnt, entriesOff, entriesBytes);
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

    // Work on a local copy so USA fixups don't corrupt the shared MFT buffer
    BYTE localRec[4096];
    memcpy(localRec, mftBuffer + dirRecordNum * recSize, recSize);
    PBYTE dirRec = localRec;

    MFT_FILE_RECORD* fileRec = (MFT_FILE_RECORD*)dirRec;
    if (g_dbg) {
        wprintf(L"    [walk] rec=%llu sig=%c%c%c%c flags=0x%04X usa=%u/%u firstAttr=0x%X\n",
            dirRecordNum, dirRec[0], dirRec[1], dirRec[2], dirRec[3],
            fileRec->flags, fileRec->sequenceOffset, fileRec->fixupCount,
            fileRec->firstAttrOffset);
    }
    if (memcmp(fileRec->signature, "FILE", 4) != 0) return FALSE;
    if (!(fileRec->flags & 0x0002)) return FALSE; // Not a directory

    // Restore true bytes at sector ends (update-sequence array)
    ApplyUsaFixups(dirRec, recSize, fileRec->sequenceOffset,
        fileRec->fixupCount, ntfs->bytesPerSector);

    DWORD indexBlockSize = 4096;

    // Walk attributes: $INDEX_ROOT (0x90) first, then $INDEX_ALLOCATION (0xA0)
    PBYTE attrPtr = dirRec + fileRec->firstAttrOffset;
    while (*(PDWORD)attrPtr != 0xFFFFFFFF && *(PDWORD)attrPtr != 0) {
        ATTR_HEADER* attrHdr = (ATTR_HEADER*)attrPtr;

        if (attrHdr->type == ATTR_INDEX_ROOT && !attrHdr->nonResident) {
            ATTR_RESIDENT* resAttr = (ATTR_RESIDENT*)attrPtr;
            PBYTE indexRoot = (PBYTE)attrPtr + resAttr->valueOffset;
            if (g_dbg) wprintf(L"    [idxroot] valueLen=%u\n", resAttr->valueLength);
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

    // Skip optional "X:" drive prefix and leading backslash
    PWSTR start = pathCopy;
    if (((start[0] >= L'a' && start[0] <= L'z') ||
         (start[0] >= L'A' && start[0] <= L'Z')) && start[1] == L':')
        start += 2;
    if (start[0] == L'\\') start++;
    token = wcstok_s(start, L"\\", &context);

    while (token != NULL) {
        if (g_dbg) wprintf(L"  [walk] find \"%ls\" in rec %llu\n", token, currentRecord);
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
                    if (offSize > 0 && offSize < 8 &&
                        (runOffset & (1LL << (offSize * 8 - 1)))) {
                        runOffset |= ~((1LL << (offSize * 8)) - 1);
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
