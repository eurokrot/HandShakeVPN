using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace HandShake.Release
{
    public static class ReleaseSecurity
    {
        public static bool Verify(string version, string hash, long size, string signature)
        {
            if (version == null || !Regex.IsMatch(version, @"^[0-9A-Za-z][0-9A-Za-z._-]{0,31}$") ||
                hash == null || !Regex.IsMatch(hash, @"^[0-9a-f]{64}$") || size < 1024 || size > 120L * 1024 * 1024 || String.IsNullOrEmpty(signature)) return false;
            try
            {
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.PersistKeyInCsp = false;
                    rsa.FromXmlString(UpdateTrust.PublicKeyXml);
                    byte[] message = Encoding.UTF8.GetBytes(version + "\n" + hash + "\n" + size.ToString(CultureInfo.InvariantCulture) + "\n");
                    return rsa.VerifyData(message, CryptoConfig.MapNameToOID("SHA256"), Convert.FromBase64String(signature));
                }
            }
            catch (FormatException) { return false; }
            catch (CryptographicException) { return false; }
        }
    }
}
