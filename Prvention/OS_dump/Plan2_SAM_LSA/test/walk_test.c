// walk_test.c — validate the raw-NTFS directory walk + DataRun extraction only
// (no credential handling). Extracts a benign file and prints size + magic.
// Usage: walk_test.exe [path]   (default \Windows\System32\kernel32.dll)
#include "../../shared/common.h"

int wmain(int argc, wchar_t** argv) {
    PWSTR target = argc > 1 ? argv[1] : L"\\Windows\\System32\\kernel32.dll";

    HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, NULL);
    if (hVol == INVALID_HANDLE_VALUE) {
        wprintf(L"[ERR] open \\\\.\\C: failed (err=%d) — need admin\n", GetLastError());
        return 1;
    }

    NTFS_CONTEXT ctx;
    if (!ParseNtfsBoot(hVol, &ctx)) return 1;
    wprintf(L"[i] cluster=%d, mftRecordSize=%d\n", ctx.clusterSize, ctx.mftRecordSize);

    PBYTE mft = NULL; SIZE_T mftSz = 0;
    if (!ReadMft(hVol, &ctx, &mft, &mftSz)) return 1;
    wprintf(L"[i] MFT read: %lld MB\n", mftSz / 1024 / 1024);

    HIVE_DATA h = {0};
    BOOL ok = ExtractFileFromNtfs(hVol, &ctx, mft, mftSz, target, &h);
    wprintf(L"[%s] %s (%lld bytes)\n", ok ? L"OK" : L"FAIL", target, h.size);
    if (ok && h.size >= 2) {
        wprintf(L"    first bytes: %02X %02X\n", h.data[0], h.data[1]);
    }

    VirtualFree(mft, 0, MEM_RELEASE);
    FreeHiveData(&h);
    CloseHandle(hVol);
    return ok ? 0 : 1;
}
