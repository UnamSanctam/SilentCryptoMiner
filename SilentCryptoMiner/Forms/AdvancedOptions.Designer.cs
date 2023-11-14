using System;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Windows.Forms;
using Microsoft.VisualBasic.CompilerServices;

namespace SilentCryptoMiner
{
    [DesignerGenerated()]
    public partial class AdvancedOptions : Form
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(AdvancedOptions));
            this.formAdvancedOptions = new MephTheme();
            this.labelAdvancedOptionUPXPack = new System.Windows.Forms.Label();
            this.toggleUPXPack = new MephToggleSwitch();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.labelAdvancedOptionRootkit = new System.Windows.Forms.Label();
            this.toggleRootkit = new MephToggleSwitch();
            this.labelAdvancedOptionRunInstall = new System.Windows.Forms.Label();
            this.toggleRunInstall = new MephToggleSwitch();
            this.formAdvancedOptions.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            this.SuspendLayout();
            // 
            // formAdvancedOptions
            // 
            this.formAdvancedOptions.AccentColor = System.Drawing.Color.DarkRed;
            this.formAdvancedOptions.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.formAdvancedOptions.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(28)))), ((int)(((byte)(28)))), ((int)(((byte)(28)))));
            this.formAdvancedOptions.Controls.Add(this.labelAdvancedOptionUPXPack);
            this.formAdvancedOptions.Controls.Add(this.toggleUPXPack);
            this.formAdvancedOptions.Controls.Add(this.pictureBox1);
            this.formAdvancedOptions.Controls.Add(this.labelAdvancedOptionRootkit);
            this.formAdvancedOptions.Controls.Add(this.toggleRootkit);
            this.formAdvancedOptions.Controls.Add(this.labelAdvancedOptionRunInstall);
            this.formAdvancedOptions.Controls.Add(this.toggleRunInstall);
            this.formAdvancedOptions.Font = new System.Drawing.Font("Segoe UI", 9.5F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(128)));
            this.formAdvancedOptions.Location = new System.Drawing.Point(0, 0);
            this.formAdvancedOptions.Name = "formAdvancedOptions";
            this.formAdvancedOptions.Size = new System.Drawing.Size(273, 307);
            this.formAdvancedOptions.SubHeader = "";
            this.formAdvancedOptions.TabIndex = 0;
            this.formAdvancedOptions.Text = "Advanced Options";
            // 
            // labelAdvancedOptionUPXPack
            // 
            this.labelAdvancedOptionUPXPack.AutoEllipsis = true;
            this.labelAdvancedOptionUPXPack.BackColor = System.Drawing.Color.Transparent;
            this.labelAdvancedOptionUPXPack.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelAdvancedOptionUPXPack.ForeColor = System.Drawing.Color.Gray;
            this.labelAdvancedOptionUPXPack.Location = new System.Drawing.Point(13, 99);
            this.labelAdvancedOptionUPXPack.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelAdvancedOptionUPXPack.Name = "labelAdvancedOptionUPXPack";
            this.labelAdvancedOptionUPXPack.Size = new System.Drawing.Size(170, 17);
            this.labelAdvancedOptionUPXPack.TabIndex = 151;
            this.labelAdvancedOptionUPXPack.Text = "UPX-pack embedded files:";
            // 
            // toggleUPXPack
            // 
            this.toggleUPXPack.BackColor = System.Drawing.Color.Transparent;
            this.toggleUPXPack.Checked = true;
            this.toggleUPXPack.ForeColor = System.Drawing.Color.Black;
            this.toggleUPXPack.Location = new System.Drawing.Point(188, 96);
            this.toggleUPXPack.Margin = new System.Windows.Forms.Padding(2);
            this.toggleUPXPack.Name = "toggleUPXPack";
            this.toggleUPXPack.Size = new System.Drawing.Size(50, 24);
            this.toggleUPXPack.TabIndex = 150;
            // 
            // pictureBox1
            // 
            this.pictureBox1.BackColor = System.Drawing.Color.Transparent;
            this.pictureBox1.Image = global::SilentCryptoMiner.Properties.Resources.microsoft_admin;
            this.pictureBox1.Location = new System.Drawing.Point(243, 125);
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.Size = new System.Drawing.Size(20, 20);
            this.pictureBox1.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.pictureBox1.TabIndex = 149;
            this.pictureBox1.TabStop = false;
            // 
            // labelAdvancedOptionRootkit
            // 
            this.labelAdvancedOptionRootkit.AutoEllipsis = true;
            this.labelAdvancedOptionRootkit.BackColor = System.Drawing.Color.Transparent;
            this.labelAdvancedOptionRootkit.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelAdvancedOptionRootkit.ForeColor = System.Drawing.Color.Gray;
            this.labelAdvancedOptionRootkit.Location = new System.Drawing.Point(13, 125);
            this.labelAdvancedOptionRootkit.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelAdvancedOptionRootkit.Name = "labelAdvancedOptionRootkit";
            this.labelAdvancedOptionRootkit.Size = new System.Drawing.Size(157, 17);
            this.labelAdvancedOptionRootkit.TabIndex = 148;
            this.labelAdvancedOptionRootkit.Text = "Use Rootkit (Hide Miner):";
            // 
            // toggleRootkit
            // 
            this.toggleRootkit.BackColor = System.Drawing.Color.Transparent;
            this.toggleRootkit.Checked = false;
            this.toggleRootkit.ForeColor = System.Drawing.Color.Black;
            this.toggleRootkit.Location = new System.Drawing.Point(188, 123);
            this.toggleRootkit.Margin = new System.Windows.Forms.Padding(2);
            this.toggleRootkit.Name = "toggleRootkit";
            this.toggleRootkit.Size = new System.Drawing.Size(50, 24);
            this.toggleRootkit.TabIndex = 147;
            // 
            // labelAdvancedOptionRunInstall
            // 
            this.labelAdvancedOptionRunInstall.AutoEllipsis = true;
            this.labelAdvancedOptionRunInstall.BackColor = System.Drawing.Color.Transparent;
            this.labelAdvancedOptionRunInstall.Font = new System.Drawing.Font("Segoe UI", 9.5F);
            this.labelAdvancedOptionRunInstall.ForeColor = System.Drawing.Color.Gray;
            this.labelAdvancedOptionRunInstall.Location = new System.Drawing.Point(13, 72);
            this.labelAdvancedOptionRunInstall.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelAdvancedOptionRunInstall.Name = "labelAdvancedOptionRunInstall";
            this.labelAdvancedOptionRunInstall.Size = new System.Drawing.Size(170, 17);
            this.labelAdvancedOptionRunInstall.TabIndex = 118;
            this.labelAdvancedOptionRunInstall.Text = "Run miner after install:";
            // 
            // toggleRunInstall
            // 
            this.toggleRunInstall.BackColor = System.Drawing.Color.Transparent;
            this.toggleRunInstall.Checked = true;
            this.toggleRunInstall.ForeColor = System.Drawing.Color.Black;
            this.toggleRunInstall.Location = new System.Drawing.Point(188, 69);
            this.toggleRunInstall.Margin = new System.Windows.Forms.Padding(2);
            this.toggleRunInstall.Name = "toggleRunInstall";
            this.toggleRunInstall.Size = new System.Drawing.Size(50, 24);
            this.toggleRunInstall.TabIndex = 117;
            // 
            // AdvancedOptions
            // 
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.None;
            this.ClientSize = new System.Drawing.Size(273, 307);
            this.Controls.Add(this.formAdvancedOptions);
            this.Font = new System.Drawing.Font("Microsoft Sans Serif", 5.729167F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(128)));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.MaximumSize = new System.Drawing.Size(436, 307);
            this.MinimizeBox = false;
            this.Name = "AdvancedOptions";
            this.Opacity = 0.95D;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Advanced";
            this.TransparencyKey = System.Drawing.Color.Fuchsia;
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.advancedOptions_FormClosing);
            this.formAdvancedOptions.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            this.ResumeLayout(false);

        }

        internal MephTheme formAdvancedOptions;
        internal Label labelAdvancedOptionRunInstall;
        internal MephToggleSwitch toggleRunInstall;
        internal PictureBox pictureBox1;
        internal Label labelAdvancedOptionRootkit;
        internal MephToggleSwitch toggleRootkit;
        internal Label labelAdvancedOptionUPXPack;
        internal MephToggleSwitch toggleUPXPack;
    }
}