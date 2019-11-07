using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace ECDsaMicrosoft
{
    public class ECDSA
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

        public static SigningCredentials CreateSigningCredentials(string privateKey, string kid)
        {
            var eCDsa = LoadPrivateKey(privateKey);
            return CreateSigningCredentials(eCDsa, kid);
        }
        public static SigningCredentials CreateSigningCredentials(ECDsa eCDsa,string kid)
        {
            var signingCredentials = new SigningCredentials(
                        new ECDsaSecurityKey(eCDsa) {KeyId= kid}, SecurityAlgorithms.EcdsaSha256);
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
