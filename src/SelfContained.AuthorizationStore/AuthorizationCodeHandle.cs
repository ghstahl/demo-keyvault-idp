using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using ZeroFormatter;

namespace SelfContained.AuthorizationStore
{


    [ZeroFormattable]
    public class MinimalData
    {
        [Index(0)]
        public virtual string Nonce { get; set; }
        [Index(1)]
        public virtual string StateHash { get; set; }
        [Index(2)]
        public virtual string Subject { get; set; }
        [Index(3)]
        public virtual IList<string> RequestedScopes { get; set; }
    }

    public partial class Subject
    {
        [JsonProperty("AuthenticationType")]
        public virtual string AuthenticationType { get; set; }

        [JsonProperty("Claims")]
        public virtual IList<ClaimHandle> Claims { get; set; }
    }


    public partial class ClaimHandle
    {
        [JsonProperty("Type")]
        public virtual string Type { get; set; }

        [JsonProperty("Value")]
        public virtual string Value { get; set; }
    }

    public partial class AuthorizationCodeHandle
    {
        [JsonProperty("CreationTime")]
        public virtual string CreationTime { get; set; }

        [JsonProperty("Lifetime")]
        public virtual long Lifetime { get; set; }

        [JsonProperty("ClientId")]
        public virtual string ClientId { get; set; }

        [JsonProperty("IsOpenId")]
        public virtual bool IsOpenId { get; set; }

        [JsonProperty("RequestedScopes")]
        public virtual IList<string> RequestedScopes { get; set; }

        [JsonProperty("RedirectUri")]
        public virtual string RedirectUri { get; set; }

        [JsonProperty("Nonce")]
        public virtual string Nonce { get; set; }

        [JsonProperty("StateHash")]
        public virtual string StateHash { get; set; }

        [JsonProperty("SessionId")]
        public virtual string SessionId { get; set; }

        [JsonProperty("Subject")]
        public virtual Subject Subject { get; set; }
        
    }
   
}
