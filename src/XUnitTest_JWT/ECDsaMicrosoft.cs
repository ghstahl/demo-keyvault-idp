using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace XUnitTest_JWT
{
    internal static class Constants
    {
        public static class CurveOids
        {
            public const string P256 = "1.2.840.10045.3.1.7";
            public const string P384 = "1.3.132.0.34";
            public const string P521 = "1.3.132.0.35";
        }
    }
 
    public class ECDsaMicrosoft
    {
        public static (string privateKey, string publicKey, string alg) GenerateKeys(string keyName)
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

            return (privateKey, publicKey, SecurityAlgorithms.EcdsaSha256);
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
        internal static string GetCrvValueFromCurve(ECCurve curve)
        {
            return curve.Oid.Value switch
            {
                Constants.CurveOids.P256 => JsonWebKeyECTypes.P256,
                Constants.CurveOids.P384 => JsonWebKeyECTypes.P384,
                Constants.CurveOids.P521 => JsonWebKeyECTypes.P521,
                _ => throw new InvalidOperationException($"Unsupported curve type of {curve.Oid.Value} - {curve.Oid.FriendlyName}"),
            };
        }
        internal static string GetSecurityAlgorithmFromCurve(ECCurve curve)
        {
            return curve.Oid.Value switch
            {
                Constants.CurveOids.P256 => SecurityAlgorithms.EcdsaSha256,
                Constants.CurveOids.P384 => SecurityAlgorithms.EcdsaSha384,
                Constants.CurveOids.P521 => SecurityAlgorithms.EcdsaSha512,
                _ => throw new InvalidOperationException($"Unsupported curve type of {curve.Oid.Value} - {curve.Oid.FriendlyName}"),
            };
        }
        public static JsonWebKey CreateJsonWebKey(SecurityKey securityKey)
        {
            if (securityKey is ECDsaSecurityKey ecdsaKey)
            {
                

                var parameters = ecdsaKey.ECDsa.ExportParameters(false);
                var x = Base64Url.Encode(parameters.Q.X);
                var y = Base64Url.Encode(parameters.Q.Y);
                var jwk = new JsonWebKey
                {
                    Kty = "EC",
                    Use = "sig",
                    Kid = ecdsaKey.KeyId,
                    X = x,
                    Y = y,
                    Crv = GetCrvValueFromCurve(parameters.Curve),
                    Alg = GetSecurityAlgorithmFromCurve(parameters.Curve)
                };

            }
            return null;
        }
    }
 }
