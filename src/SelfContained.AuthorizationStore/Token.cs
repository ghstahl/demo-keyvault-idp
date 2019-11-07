using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SelfContained.AuthorizationStore
{
    internal class Token
    {
        public readonly string Value;
        public readonly DateTime Expires;
        public readonly byte[] Data;
        public byte[] Signature { private set; get; }

        public Token(string value, DateTime expires)
        {
            Value = value;
            Expires = expires;
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write(Expires.Ticks);
                writer.Write(Value);
                Data = ms.ToArray();
            }
        }

        private void Sign(string privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                rsa.FromXmlString(privateKey);
                Signature = rsa.SignData(Data, sha1);
            }
        }

        public string GetTokenString(string privateKey)
        {
            if (Signature == null)
            {
                Sign(privateKey);
            }
            return Convert.ToBase64String(Data.Concat(Signature).ToArray());
        }

        public static Token FromTokenString(string tokenString, string key)
        {
            var buffer = Convert.FromBase64String(tokenString);
            var data = buffer.Take(buffer.Length - 128).ToArray();
            var sig = buffer.Skip(data.Length).Take(128).ToArray();
            using (var rsa = new RSACryptoServiceProvider())
            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                rsa.FromXmlString(key);
                if (rsa.VerifyData(data, sha1, sig))
                {
                    using (var ms = new MemoryStream(data))
                    using (var reader = new BinaryReader(ms))
                    {
                        var ticks = reader.ReadInt64();
                        var value = reader.ReadString();
                        var expires = new DateTime(ticks);
                        if (expires > DateTime.Now)
                        {
                            return new Token(value, expires);
                        }
                    }
                }
            }
            return null;
        }
        public static string GetPrivateKey()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                return rsa.ToXmlString(true);
            }
        }
    }
}
