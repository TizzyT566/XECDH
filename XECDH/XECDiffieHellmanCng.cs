using System.IO;

namespace System.Security.Cryptography
{
    public static class XECDiffieHellmanCng
    {
        public static CngKey GenerateECDiffieHellmanP521Key()
        {
            CngKeyCreationParameters cngKeyCreationParameters = new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.AllowPlaintextArchiving };
            return CngKey.Create(CngAlgorithm.ECDiffieHellmanP521, null, cngKeyCreationParameters);
        }

        public static void SaveEncryptedEccFullPrivateBlob(this CngKey @this, string path, string passphrase)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;
                using (SHA384 passPhraseToKeyIV = new SHA384Managed())
                {
                    byte[] keyiv = passPhraseToKeyIV.ComputeHash(Text.Encoding.UTF8.GetBytes(passphrase));
                    byte[] key = new byte[32];
                    Array.Copy(keyiv, 0, key, 0, 32);
                    byte[] iv = new byte[16];
                    Array.Copy(keyiv, 0, iv, 32, 16);
                    aes.Key = key;
                    aes.IV = iv;
                }
                using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                File.WriteAllBytes(path, PerformCryptography(@this.Export(CngKeyBlobFormat.EccFullPrivateBlob), encryptor));
            };
        }

        public static CngKey LoadEncryptedEccFullPrivateBlob(string path, string passphrase)
        {
            using (var aes = Aes.Create())
            using (SHA384 passPhraseToKeyIV = new SHA384Managed())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;

                byte[] keyiv = passPhraseToKeyIV.ComputeHash(Text.Encoding.UTF8.GetBytes(passphrase));
                byte[] key = new byte[32];
                Array.Copy(keyiv, 0, key, 0, 32);
                byte[] iv = new byte[16];
                Array.Copy(keyiv, 0, iv, 32, 16);
                aes.Key = key;
                aes.IV = iv;

                using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                return CngKey.Import(PerformCryptography(File.ReadAllBytes(path), decryptor), CngKeyBlobFormat.EccFullPrivateBlob);
            };
        }

        private static byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
        {
            using var ms = new MemoryStream();
            using var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write);
            cryptoStream.Write(data, 0, data.Length);
            cryptoStream.FlushFinalBlock();
            return ms.ToArray();
        }

        public static byte[] DeriveKey(ECDiffieHellmanCng personalECDH, ECDiffieHellmanCng ephemeralECDH, ECDiffieHellmanPublicKey otherPartyPublicKey, ECDiffieHellmanPublicKey otherPartyEphemeralPublicKey, CngAlgorithm innerHashAlgorithm)
        {
            byte[] keyA, keyB;
            ephemeralECDH.HashAlgorithm = personalECDH.HashAlgorithm = innerHashAlgorithm;
            ephemeralECDH.KeyDerivationFunction = personalECDH.KeyDerivationFunction;
            keyA = personalECDH.DeriveKeyMaterial(otherPartyEphemeralPublicKey);
            keyB = ephemeralECDH.DeriveKeyMaterial(otherPartyPublicKey);
            static bool KeySort(byte[] keyA, byte[] keyB)
            {
                for (int i = 0; i < keyA.Length; i++)
                    if (keyA[i] < keyB[i]) return true;
                    else if (keyA[i] > keyB[i]) return false;
                return true;
            }
            byte[] derivedKey = new byte[keyA.Length + keyB.Length];
            if (KeySort(keyA, keyB))
            {
                Array.Copy(keyA, 0, derivedKey, 0, keyA.Length);
                Array.Copy(keyB, 0, derivedKey, keyA.Length, keyB.Length);
            }
            else
            {
                Array.Copy(keyB, 0, derivedKey, 0, keyB.Length);
                Array.Copy(keyA, 0, derivedKey, keyB.Length, keyA.Length);
            }
            return derivedKey;
        }
    }
}
