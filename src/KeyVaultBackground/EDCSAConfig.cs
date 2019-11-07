using System;

namespace KeyVaultBackground
{
    public class EDCSAConfig
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime Expiration { get; set; }
    }
}
