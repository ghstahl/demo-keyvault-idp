using ECDsaMicrosoft;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Sec;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace XUnitTest_JWT
{
    public class UnitTest_VariousJWT
    {
        [Fact]
        public void JWT_Ecdsa_Microsoft()
        {
            var (privateKey, publicKey,alg) = ECDsaMicrosoft.ECDSA.GenerateKeys("MyKey");
            var credentials = ECDsaMicrosoft.ECDSA.CreateSigningCredentials(privateKey,"0");
            var issuerSigningKey = ECDsaMicrosoft.ECDSA.CreateSecurityKey(publicKey);

            var tokenHandler = new JwtSecurityTokenHandler();
            var symmetricKey = Guid.NewGuid().ToByteArray();
            var nameIdentifier = "5094df23-78a6-486d-bd39-7923bc2218ed";
            var now = DateTime.UtcNow;

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                       {
                            new Claim(ClaimTypes.NameIdentifier, nameIdentifier),
                            new Claim(ClaimTypes.Role, "Author"),
                            new Claim("norton::action", Guid.NewGuid().ToString()),
                       }),
                Issuer = "self",
                Audience = "self",
                Expires = now.AddMinutes(2),
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

            var jwk = ECDsaMicrosoft.ECDSA.CreateJsonWebKey(issuerSigningKey);
        }

        [Fact]
        public void JWT_Ecdsa_BouncyCastle()
        {
            // https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html
            const string privateKey = "4601b0f043ad0ce1ee2f57a3fffea948fb19f2a2d0da877c10a145f06beb66df";
            const string publicKey  = "0448f42316c9fae29e900f325dfb936f0c8ebceef809865dfca75e4be0b25294bee39dc3924e3fbfee057f6403a0c0fa9cc2e9771ca2cf353291dbf7a5be6ce326";

            var privateECDsa = ECDsaBouncyCastle.LoadPrivateKey(privateKey);
            var publicECDsa = ECDsaBouncyCastle.LoadPublicKey(publicKey);

            var jwt = ECDsaBouncyCastle.CreateSignedJwt(privateECDsa);
            var isValid = ECDsaBouncyCastle.VerifySignedJwt(publicECDsa, jwt);
            isValid.Should().BeTrue();

        }


        [Fact]
        public void JWT_SymmetricSecurityKey()
        {
            var symmetricKey = Guid.NewGuid().ToByteArray();
            var credentials = new SigningCredentials(new SymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha256Signature);
            var issuerSigningKey = new SymmetricSecurityKey(symmetricKey);

            var nameIdentifier = "5094df23-78a6-486d-bd39-7923bc2218ed";
            var now = DateTime.UtcNow;

            var tokenHandler = new JwtSecurityTokenHandler();
          
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
                Expires = now.AddMinutes(2),
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
