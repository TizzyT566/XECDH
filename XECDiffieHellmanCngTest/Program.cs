
using System;
using System.Linq;
using System.Security.Cryptography;

using CngKey tempKey = XECDiffieHellmanCng.GenerateECDiffieHellmanP521Key();

tempKey.SaveEncryptedEccFullPrivateBlob(@"C:\Users\tizzy\Desktop\cngkey.enc", "pokemon");
CngKey keyA = XECDiffieHellmanCng.LoadEncryptedEccFullPrivateBlob(@"C:\Users\tizzy\Desktop\cngkey.enc", "pokemon");



ECDiffieHellmanCng personal = new(keyA);



using CngKey keyB = XECDiffieHellmanCng.GenerateECDiffieHellmanP521Key();
ECDiffieHellmanCng ephemeral = new(keyB);



using CngKey theirKeyA = CngKey.Create(CngAlgorithm.ECDiffieHellmanP521);
ECDiffieHellmanCng theirPersonal = new(theirKeyA);
using CngKey theirKeyB = CngKey.Create(CngAlgorithm.ECDiffieHellmanP521);
ECDiffieHellmanCng theirEphemeral = new(theirKeyB);



byte[] derivedKeyA = XECDiffieHellmanCng.DeriveKey(personal, ephemeral, theirPersonal.PublicKey, theirEphemeral.PublicKey, CngAlgorithm.Sha512);
byte[] derivedKeyB = XECDiffieHellmanCng.DeriveKey(theirPersonal, theirEphemeral, personal.PublicKey, ephemeral.PublicKey, CngAlgorithm.Sha512);

Console.WriteLine(derivedKeyA.SequenceEqual(derivedKeyB));
Console.WriteLine(derivedKeyA.Length * 8);

foreach (byte b in derivedKeyA) Console.Write($"{b:000}, ");
Console.WriteLine();
Console.WriteLine();
foreach (byte b in derivedKeyB) Console.Write($"{b:000}, ");

Console.WriteLine();
Console.WriteLine();

derivedKeyA = XECDiffieHellmanCng.DeriveKey(personal, ephemeral, theirPersonal.PublicKey, theirEphemeral.PublicKey, CngAlgorithm.Sha512);
derivedKeyB = XECDiffieHellmanCng.DeriveKey(theirPersonal, theirEphemeral, personal.PublicKey, ephemeral.PublicKey, CngAlgorithm.Sha512);

Console.WriteLine(derivedKeyA.SequenceEqual(derivedKeyB));
Console.WriteLine(derivedKeyA.Length * 8);

foreach (byte b in derivedKeyA) Console.Write($"{b:000}, ");
Console.WriteLine();
Console.WriteLine();
foreach (byte b in derivedKeyB) Console.Write($"{b:000}, ");

Console.ReadLine();