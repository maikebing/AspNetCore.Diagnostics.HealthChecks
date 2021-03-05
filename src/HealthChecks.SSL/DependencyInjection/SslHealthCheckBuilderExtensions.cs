using System;
using System.Collections.Generic;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using HealthChecks.Ssl;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class SslHealthCheckBuilderExtensions
    {

        const string NAME = "ssl_cert";

        /// <summary>
        /// Add a health check for Ssl Certificate.
        /// </summary>
        /// <param name="builder">The <see cref="IHealthChecksBuilder"/>.</param>
        /// <param name="host">Hostname of Ssl certificate to check</param>
        /// <param name="port">Port to use for check certificate. Optional. Default 443</param>
        /// <param name="daysBeforeExpireDegraded">Days before expire date of certificate warning with degraded state. Optional. Default 60</param>
        /// <param name="name">The health check name. Optional. If <c>null</c> the type name 'sqlserver' will be used for the name.</param>
        /// <param name="failureStatus">
        /// The <see cref="HealthStatus"/> that should be reported when the health check fails. Optional. If <c>null</c> then
        /// the default status of <see cref="HealthStatus.Unhealthy"/> will be reported.
        /// </param>
        /// <param name="tags">A list of tags that can be used to filter sets of health checks. Optional.</param>
        /// <param name="timeout">An optional System.TimeSpan representing the timeout of the check.</param>
        /// <returns>The <see cref="IHealthChecksBuilder"/>.</returns>
        public static IHealthChecksBuilder AddSSLCertificate(this IHealthChecksBuilder builder, string host, int port = 443, int daysBeforeExpireDegraded = 60, string name = default, HealthStatus? failureStatus = default, IEnumerable<string> tags = default, TimeSpan? timeout = default)
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
