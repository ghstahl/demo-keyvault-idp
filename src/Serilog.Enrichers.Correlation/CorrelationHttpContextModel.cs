using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System.Collections.Generic;
using System.Security.Claims;

namespace Serilog.Enrichers.Correlation
{
    public class CorrelationHttpContextModel
    {
        public string CorrelationId { get; internal set; }
    }
}
