using System.IO;

namespace SilentCryptoMiner.Program
{
    internal class Utils
    {
        internal static void deleteFiles(string[] files)
        {
            foreach (var file in files)
                File.Delete(file);
        }
    }
}