using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace XUnitTest_JWT
{
    public class ECDsaMicrosoft
    {
        public static (string privateKey, string publicKey) GenerateKeys(string keyName)
        {
            // Create Private - Public Key pair
            var key = CngKey.Create(CngAlgorithm.ECDsaP256, keyName,
                new CngKeyCreationParameters
                {
                    KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                    KeyUsage = CngKeyUsages.AllUsages,
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport
                });
            var privateKey = Convert.ToBase64String(key.Export(CngKeyBlobFormat.EccPrivateBlob));
            var publicKey = Convert.ToBase64String(key.Export(CngKeyBlobFormat.EccPublicBlob));

            return (privateKey, publicKey);
        }
        public static ECDsa LoadPrivateKey(string privateKey)
        {
            var ecDsaCng = new ECDsaCng(CngKey.Import(Convert.FromBase64String(privateKey), CngKeyBlobFormat.EccPrivateBlob))
            {
                HashAlgorithm = CngAlgorithm.ECDsaP256
            };
            return ecDsaCng;
        }
        public static SecurityKey CreateSecurityKey(string publicKey)
        {
            var eCDsa = LoadPublicKey(publicKey);
            return CreateSecurityKey(eCDsa);
        }
        public static SecurityKey CreateSecurityKey(ECDsa eCDsa)
        {
            var issuerSigningKey = new ECDsaSecurityKey(eCDsa);
            return issuerSigningKey;
        }

        public static SigningCredentials CreateSigningCredentials(string privateKey)
        {
            var eCDsa = LoadPrivateKey(privateKey);
            return CreateSigningCredentials(eCDsa);
        }
        public static SigningCredentials CreateSigningCredentials(ECDsa eCDsa)
        {
            var signingCredentials = new SigningCredentials(
                        new ECDsaSecurityKey(eCDsa), SecurityAlgorithms.EcdsaSha256);
            return signingCredentials;

        }
        public static ECDsa LoadPublicKey(string publicKey)
        {
            var ecDsaCng = new ECDsaCng(CngKey.Import(Convert.FromBase64String(publicKey), CngKeyBlobFormat.EccPublicBlob));
            ecDsaCng.HashAlgorithm = CngAlgorithm.ECDsaP256;
            return ecDsaCng;
        }
    }
 }
