using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Sec;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using Xunit;

namespace XUnitTest_JWT
{
    public class UnitTest_VariousJWT
    {
        [Fact]
        public void JWT_Ecdsa()
        {
            // https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html
            const string privateKey = "4601b0f043ad0ce1ee2f57a3fffea948fb19f2a2d0da877c10a145f06beb66df";
            const string publicKey  = "0448f42316c9fae29e900f325dfb936f0c8ebceef809865dfca75e4be0b25294bee39dc3924e3fbfee057f6403a0c0fa9cc2e9771ca2cf353291dbf7a5be6ce326";

            var privateECDsa = LoadPrivateKey(FromHexString(privateKey));
            var publicECDsa = LoadPublicKey(FromHexString(publicKey));

            var jwt = CreateSignedJwt(privateECDsa);
            var isValid = VerifySignedJwt(publicECDsa, jwt);
            isValid.Should().BeTrue();

        }

        // https://stackoverflow.com/questions/311165/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-and-vice-versa
        private static byte[] FromHexString(string hex)
        {
            var numberChars = hex.Length;
            var hexAsBytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
                hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            return hexAsBytes;
        }

        private static ECDsa LoadPrivateKey(byte[] key)
        {
            var privKeyInt = new Org.BouncyCastle.Math.BigInteger(+1, key);
            var parameters = SecNamedCurves.GetByName("secp256r1");
            var ecPoint = parameters.G.Multiply(privKeyInt);
            var privKeyX = ecPoint.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned();
            var privKeyY = ecPoint.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned();

            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privKeyInt.ToByteArrayUnsigned(),
                Q = new ECPoint
                {
                    X = privKeyX,
                    Y = privKeyY
                }
            });
        }

        private static ECDsa LoadPublicKey(byte[] key)
        {
            var pubKeyX = key.Skip(1).Take(32).ToArray();
            var pubKeyY = key.Skip(33).ToArray();

            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = pubKeyX,
                    Y = pubKeyY
                }
            });
        }

        private static string CreateSignedJwt(ECDsa eCDsa)
        {
            var now = DateTime.UtcNow;
            var tokenHandler = new JwtSecurityTokenHandler();

            var jwtToken = tokenHandler.CreateJwtSecurityToken(
                issuer: "me",
                audience: "you",
                subject: null,
                notBefore: now,
                expires: now.AddMinutes(30),
                issuedAt: now,
                signingCredentials: new SigningCredentials(new ECDsaSecurityKey(eCDsa), SecurityAlgorithms.EcdsaSha256));

            return tokenHandler.WriteToken(jwtToken);
        }

        private static bool VerifySignedJwt(ECDsa eCDsa, string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var claimsPrincipal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                IssuerSigningKey = new ECDsaSecurityKey(eCDsa)
            }, out var parsedToken);

            return claimsPrincipal.Identity.IsAuthenticated;
        }
        [Fact]
        public void JWT_SymmetricSecurityKey()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var symmetricKey = Guid.NewGuid().ToByteArray();
            var nameIdentifier = "5094df23-78a6-486d-bd39-7923bc2218ed";
            var now = DateTime.UtcNow;

            var credentials = new SigningCredentials(new SymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha256Signature);
            var issuerSigningKey = new SymmetricSecurityKey(symmetricKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                       {
                            new Claim(ClaimTypes.NameIdentifier, nameIdentifier),
                            new Claim(ClaimTypes.Role, "Author"),
                            new Claim("norton::action", Guid.NewGuid().ToString()),
                       }),
                Issuer = "self",
                Audience="self",
                Expires = DateTime.UtcNow.AddMinutes(2),
                SigningCredentials = credentials


            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            var validationParameters = new TokenValidationParameters()
            {
                ValidAudiences = new[] { "http://www.example.com" },
                IssuerSigningKey = issuerSigningKey,
                ValidIssuer = "self",
                ValidateLifetime = true,
                ValidateAudience = true,
                ValidAudience = "self"
            };
            SecurityToken validatedToken = null;
            // will throw if lifetime outside of cpu clock skew
            ClaimsPrincipal principal;
            Action act = () => {
                principal = tokenHandler.ValidateToken(tokenString, validationParameters, out validatedToken);
            };
            act.Should().NotThrow();
         

        }
    }
}
