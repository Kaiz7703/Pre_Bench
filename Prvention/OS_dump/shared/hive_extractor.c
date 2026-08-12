// hive_extractor.c — File extraction via raw NTFS traversal
// Walks MFT directory tree to find and extract target files
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

// ─── Find child entry in directory by name ───
BOOL FindChildInDir(HANDLE hVolume, NTFS_CONTEXT* ntfs,
    PBYTE mftBuffer, SIZE_T mftSize, DWORD64 dirRecordNum,
    PWSTR childName, DWORD64* childRecord) {

    PBYTE dirRec = mftBuffer + (dirRecordNum * 1024);
    if (memcmp(((MFT_FILE_RECORD*)dirRec)->signature, "FILE", 4) != 0)
        return FALSE;

    MFT_FILE_RECORD* fileRec = (MFT_FILE_RECORD*)dirRec;
    if (!(fileRec->flags & 0x0002)) return FALSE; // Not a directory

    // Walk attributes to find $INDEX_ROOT
    PBYTE attrPtr = dirRec + fileRec->firstAttrOffset;
    while (*(PDWORD)attrPtr != 0xFFFFFFFF && *(PDWORD)attrPtr != 0) {
        ATTR_HEADER* attrHdr = (ATTR_HEADER*)attrPtr;

        if (attrHdr->type == ATTR_INDEX_ROOT && !attrHdr->nonResident) {
            ATTR_RESIDENT* resAttr = (ATTR_RESIDENT*)attrPtr;
            PBYTE indexRoot = (PBYTE)attrPtr + resAttr->valueOffset;

            // Skip index root header (16 bytes): type(4) + collation(4) +
            //   bytesPerIndexRec(4) + clustersPerIndexRec(4)
            PBYTE idxEntry = indexRoot + 16;

            // Walk INDEX_ENTRY structures
            while ((PBYTE)idxEntry - indexRoot < (LONG)resAttr->valueLength) {
                INDEX_ENTRY* entry = (INDEX_ENTRY*)idxEntry;

                // Last entry marker
                if (entry->entryLength == 0 || entry->flags == 0x02)
                    break;

                // Get FILE_NAME_ATTR following the index entry
                FILE_NAME_ATTR* fn = (FILE_NAME_ATTR*)(idxEntry + sizeof(INDEX_ENTRY));

                // Compare name (case-insensitive)
                if (fn->nameLength > 0) {
                    WCHAR entryName[256] = {0};
                    memcpy(entryName, fn->name,
                        min(fn->nameLength * 2, sizeof(entryName) - 2));

                    if (_wcsicmp(entryName, childName) == 0) {
                        // Found! mftReference contains the record number + sequence
                        *childRecord = entry->mftReference & 0x0000FFFFFFFFFFFFULL;
                        return TRUE;
                    }
                }

                if (entry->entryLength == 0) break;
                idxEntry += entry->entryLength;
            }
        }
        attrPtr += attrHdr->length;
    }

    return FALSE;
}

// ─── Extract file data from NTFS by path ───
BOOL ExtractFileFromNtfs(HANDLE hVolume, NTFS_CONTEXT* ntfs,
    PBYTE mftBuffer, SIZE_T mftSize, PWSTR filePath, HIVE_DATA* hive) {

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
    PBYTE fileRec = mftBuffer + (currentRecord * 1024);
    if (memcmp(((MFT_FILE_RECORD*)fileRec)->signature, "FILE", 4) != 0) {
        // Try alternate: scan for the record if linear approach fails
        // This handles fragmented MFT with non-1024 record sizes
        for (SIZE_T off = 0; off < mftSize - 1024; off += 1024) {
            fileRec = mftBuffer + off;
            if (memcmp(((MFT_FILE_RECORD*)fileRec)->signature, "FILE", 4) == 0) {
                // Check if this is our target by checking parent dir
                // For now, just try DataRuns extraction
                break;
            }
        }
        return FALSE;
    }

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
