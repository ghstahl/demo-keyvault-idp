using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Xunit;

namespace XUnitTest_JWT
{
    public class UnitTest_VariousJWT
    {
        [Fact]
        public void Test1()
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
            var principal = tokenHandler.ValidateToken(tokenString, validationParameters, out validatedToken);

        }
    }
}
