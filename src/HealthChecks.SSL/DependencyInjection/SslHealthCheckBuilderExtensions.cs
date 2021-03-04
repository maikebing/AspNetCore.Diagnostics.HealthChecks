using System;
using System.Collections.Generic;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using HealthChecks.Ssl;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class SslHealthCheckBuilderExtensions
    {

        const string NAME = "ssl_cert";
        public static IHealthChecksBuilder AddSSLCertificate(this IHealthChecksBuilder builder, string host, int port = 443, string name = default, int daysBeforeExpireDegraded = 60, HealthStatus? failureStatus = default, IEnumerable<string> tags = default, TimeSpan? timeout = default)
        {
            return builder.Add(new HealthCheckRegistration(
                name ?? NAME,
                sp => new SslHealthCheck(host, port, daysBeforeExpireDegraded),
                failureStatus,
                tags,
                timeout));
        }

    }
}
