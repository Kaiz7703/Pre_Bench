// reg_hive.c — Minimal offline registry hive navigator (nk/vk + subkey index cells)
// Mirrors impacket winregistry behavior: paths, values, classes, subkey enumeration.
// Cell offsets are relative to hive data start (first hbin at offset 0x1000).
#include "common.h"

#define HIVE_BIN_BASE 0x1000

static DWORD FindSubkeyInList(HIVE_DATA* h, DWORD listOff, PCWSTR name);
static BOOL CollectLeafLists(HIVE_DATA* h, DWORD listOff,
    PDWORD out, PDWORD outCount, DWORD maxOut);

static PBYTE Cell(HIVE_DATA* h, DWORD off) {
    if (off == 0xFFFFFFFF) return NULL;
    // cell offset points at the 4-byte size header; content follows it
    if ((SIZE_T)HIVE_BIN_BASE + off + 4 + 8 > h->size) return NULL;
    return h->data + HIVE_BIN_BASE + off + 4;
}

BOOL HiveInit(HIVE_DATA* h) {
    if (!h || !h->data || h->size < 0x1000 + 32) return FALSE;
    return memcmp(h->data, "regf", 4) == 0;
}

// Key/value names come in two encodings selected by a "compressed name" flag:
//   nk Type bit 0x20 (KEY_COMP_NAME)   → single-byte latin-1
//   vk Flags bit 0x0001 (VALUE_COMP_NAME) → single-byte latin-1
// otherwise the name is UTF-16LE. Real hives use the compressed form.
static BOOL CopyNameEnc(PBYTE src, DWORD len, BOOL singleByte, PWSTR dst, DWORD dstChars) {
    if (singleByte) {
        if (len == 0 || len > dstChars - 1) return FALSE;
        for (DWORD i = 0; i < len; i++) dst[i] = (WCHAR)src[i];
        dst[len] = 0;
        return TRUE;
    }
    if (len == 0 || len / 2 > dstChars - 1) return FALSE;
    memcpy(dst, src, len);
    dst[len / 2] = 0;
    return TRUE;
}

// Find subkey by name under nk cell; returns nk cell offset or 0xFFFFFFFF
static DWORD FindSubkey(HIVE_DATA* h, DWORD nkOff, PCWSTR name) {
    PBYTE nk = Cell(h, nkOff);
    if (!nk || memcmp(nk, "nk", 2) != 0) return 0xFFFFFFFF;

    DWORD listOff = *(PDWORD)(nk + 0x1C); // stable subkey list
    if (listOff == 0xFFFFFFFF) return 0xFFFFFFFF;

    PBYTE list = Cell(h, listOff);
    if (!list) return 0xFFFFFFFF;

    if (memcmp(list, "ri", 2) == 0) {
        // Root index: entries are sub-list cell offsets
        WORD cnt = *(PWORD)(list + 2);
        PDWORD entries = (PDWORD)(list + 4);
        for (int i = 0; i < cnt; i++) {
            DWORD r = FindSubkeyInList(h, entries[i], name);
            if (r != 0xFFFFFFFF) return r;
        }
        return 0xFFFFFFFF;
    }
    return FindSubkeyInList(h, listOff, name);
}

// Look inside one leaf list (lf/lh/li) for the named subkey
static DWORD FindSubkeyInList(HIVE_DATA* h, DWORD listOff, PCWSTR name) {
    PBYTE list = Cell(h, listOff);
    if (!list) return 0xFFFFFFFF;

    BOOL isLi = (memcmp(list, "li", 2) == 0);
    if (!isLi && memcmp(list, "lf", 2) != 0 && memcmp(list, "lh", 2) != 0)
        return 0xFFFFFFFF;

    WORD cnt = *(PWORD)(list + 2);
    PBYTE entry = list + 4;
    DWORD stride = isLi ? 4 : 8;
    WCHAR subName[512];

    for (int i = 0; i < cnt; i++) {
        DWORD childOff = *(PDWORD)entry;
        PBYTE childNk = Cell(h, childOff);
        if (childNk && memcmp(childNk, "nk", 2) == 0) {
            DWORD nameLen = *(PWORD)(childNk + 0x48);
            BOOL comp = (*(PWORD)(childNk + 2) & 0x20) != 0; // KEY_COMP_NAME
            if (CopyNameEnc(childNk + 0x4C, nameLen, comp, subName, 512) &&
                _wcsicmp(subName, name) == 0)
                return childOff;
        }
        entry += stride;
    }
    return 0xFFFFFFFF;
}

// Open a key by backslash-separated path (segments), starting from root
static DWORD OpenKeyByPath(HIVE_DATA* h, PCWSTR path) {
    DWORD rootOff = *(PDWORD)(h->data + 0x24); // regf "OffsetFirstRecord" (root cell offset)
    DWORD cur = rootOff;

    WCHAR seg[256];
    PCWSTR p = path;
    while (*p) {
        // Extract segment
        int si = 0;
        while (*p && *p != L'\\' && si < 255) seg[si++] = *p++;
        seg[si] = 0;
        if (*p == L'\\') p++;
        if (si == 0) continue;

        cur = FindSubkey(h, cur, seg);
        if (cur == 0xFFFFFFFF) return 0xFFFFFFFF;
    }
    return cur;
}

// Get a value's data under nk cell (allocates via malloc)
BOOL HiveGetValue(HIVE_DATA* h, DWORD nkOff, PCWSTR name, PBYTE* data, PDWORD dataLen) {
    PBYTE nk = Cell(h, nkOff);
    if (!nk || memcmp(nk, "nk", 2) != 0) return FALSE;

    DWORD numValues = *(PDWORD)(nk + 0x24);
    DWORD listOff = *(PDWORD)(nk + 0x28);
    if (numValues == 0 || listOff == 0xFFFFFFFF) return FALSE;

    PBYTE list = Cell(h, listOff);
    if (!list) return FALSE;

    // The value list holds numValues+1 entries (default value appended last).
    // Bound the scan by the actual list cell size (list points at cell content).
    DWORD cellBytes = (SIZE_T)HIVE_BIN_BASE + listOff <= h->size
        ? (DWORD)(h->size - HIVE_BIN_BASE - listOff) : 0;
    DWORD maxEntries = min(numValues + 1, cellBytes / 4);

    WCHAR vname[512];
    for (DWORD i = 0; i < maxEntries; i++) {
        DWORD vkOff = *(PDWORD)(list + i * 4);
        if (vkOff == 0xFFFFFFFF) continue;
        PBYTE vk = Cell(h, vkOff);
        if (!vk || memcmp(vk, "vk", 2) != 0) continue;

        DWORD nameLen = *(PWORD)(vk + 2);
        BOOL comp = (*(PWORD)(vk + 0x10) & 0x0001) != 0; // VALUE_COMP_NAME
        if (!CopyNameEnc(vk + 0x14, nameLen, comp, vname, 512)) continue;
        if (_wcsicmp(vname, name) != 0) continue;

        DWORD dSize = *(PDWORD)(vk + 4);
        DWORD dOff = *(PDWORD)(vk + 8);

        if (dSize == 0) { *data = NULL; *dataLen = 0; return TRUE; }

        if (dSize & 0x80000000) {
            // In-cell data: high bit set → data lives in the Data Offset field
            DWORD len = dSize & 0x7FFFFFFF; // 1..4 bytes
            *data = (PBYTE)malloc(4);
            if (!*data) return FALSE;
            memcpy(*data, &dOff, len);
            *dataLen = len;
            return TRUE;
        }

        if (dOff == 0xFFFFFFFF) break;
        PBYTE dCell = Cell(h, dOff);
        if (!dCell) break;
        if ((SIZE_T)HIVE_BIN_BASE + dOff + 4 + dSize > h->size)
            dSize = (DWORD)(h->size - HIVE_BIN_BASE - dOff - 4);

        *data = (PBYTE)malloc(dSize ? dSize : 1);
        if (!*data) return FALSE;
        memcpy(*data, dCell, dSize);
        *dataLen = dSize;
        return TRUE;
    }
    return FALSE;
}

BOOL HiveGetValueByPath(HIVE_DATA* h, PCWSTR keyPath, PCWSTR valueName,
    PBYTE* data, PDWORD dataLen) {
    DWORD nk = OpenKeyByPath(h, keyPath);
    if (nk == 0xFFFFFFFF) return FALSE;
    return HiveGetValue(h, nk, valueName, data, dataLen);
}

// Get a key's class string (UTF-16LE) — e.g. Lsa\JD / Skew1 / GBG / Data
BOOL HiveGetClassByPath(HIVE_DATA* h, PCWSTR keyPath, PBYTE* data, PDWORD dataLen) {
    DWORD nkOff = OpenKeyByPath(h, keyPath);
    if (nkOff == 0xFFFFFFFF) return FALSE;

    PBYTE nk = Cell(h, nkOff);
    if (!nk || memcmp(nk, "nk", 2) != 0) return FALSE;

    DWORD classLen = *(PWORD)(nk + 0x4A);
    DWORD classOff = *(PDWORD)(nk + 0x30);
    if (classLen == 0 || classOff == 0xFFFFFFFF) return FALSE;

    PBYTE cCell = Cell(h, classOff);
    if (!cCell) return FALSE;
    if ((SIZE_T)HIVE_BIN_BASE + classOff + 4 + classLen > h->size)
        return FALSE;

    *data = (PBYTE)malloc(classLen ? classLen : 1);
    if (!*data) return FALSE;
    memcpy(*data, cCell, classLen);
    *dataLen = classLen;
    return TRUE;
}

// Enumerate subkey names under a key path (each allocated, null-terminated)
DWORD HiveEnumSubkeys(HIVE_DATA* h, PCWSTR keyPath, PWSTR* names, DWORD maxNames) {
    DWORD nkOff = OpenKeyByPath(h, keyPath);
    if (nkOff == 0xFFFFFFFF) return 0;

    PBYTE nk = Cell(h, nkOff);
    if (!nk || memcmp(nk, "nk", 2) != 0) return 0;

    DWORD listOff = *(PDWORD)(nk + 0x1C);
    if (listOff == 0xFFFFFFFF) return 0;

    DWORD count = 0;
    WCHAR buf[512];

    // Collect leaves via recursive helper (ri can nest)
    DWORD leaves[4096];
    DWORD leafCount = 0;
    if (!CollectLeafLists(h, listOff, leaves, &leafCount, 4096)) return 0;

    for (DWORD li = 0; li < leafCount && count < maxNames; li++) {
        PBYTE list = Cell(h, leaves[li]);
        if (!list) continue;
        BOOL isLi = (memcmp(list, "li", 2) == 0);
        if (!isLi && memcmp(list, "lf", 2) != 0 && memcmp(list, "lh", 2) != 0)
            continue;
        WORD cnt = *(PWORD)(list + 2);
        PBYTE entry = list + 4;
        DWORD stride = isLi ? 4 : 8;
        for (int i = 0; i < cnt && count < maxNames; i++) {
            PBYTE childNk = Cell(h, *(PDWORD)entry);
            if (childNk && memcmp(childNk, "nk", 2) == 0) {
                DWORD nameLen = *(PWORD)(childNk + 0x48);
                BOOL comp = (*(PWORD)(childNk + 2) & 0x20) != 0; // KEY_COMP_NAME
                if (CopyNameEnc(childNk + 0x4C, nameLen, comp, buf, 512)) {
                    names[count] = _wcsdup(buf);
                    if (names[count]) count++;
                }
            }
            entry += stride;
        }
    }
    return count;
}

// Helper: flatten "ri" root-index cells into leaf list offsets
static BOOL CollectLeafLists(HIVE_DATA* h, DWORD listOff,
    PDWORD out, PDWORD outCount, DWORD maxOut) {
    if (*outCount >= maxOut) return TRUE;
    PBYTE list = Cell(h, listOff);
    if (!list) return FALSE;

    if (memcmp(list, "ri", 2) == 0) {
        WORD cnt = *(PWORD)(list + 2);
        PDWORD entries = (PDWORD)(list + 4);
        for (int i = 0; i < cnt; i++) {
            if (!CollectLeafLists(h, entries[i], out, outCount, maxOut))
                return FALSE;
            if (*outCount >= maxOut) break;
        }
        return TRUE;
    }
    out[(*outCount)++] = listOff;
    return TRUE;
}
