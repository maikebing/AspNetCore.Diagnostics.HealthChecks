using FluentAssertions;
using HealthChecks.Ssl;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using System.Linq;
using Xunit;

namespace UnitTests.HealthChecks.DependencyInjection.Ssl
{
    public class ssl_certificate_registration_should
    {
        [Fact]
        public void add_health_check_when_properly_configured()
        {
            var services = new ServiceCollection();
            services.AddHealthChecks()
                .AddSSLCertificate("host");

            var serviceProvider = services.BuildServiceProvider();
            var options = serviceProvider.GetService<IOptions<HealthCheckServiceOptions>>();

            var registration = options.Value.Registrations.First();
            var check = registration.Factory(serviceProvider);

            registration.Name.Should().Be("ssl_cert");
            check.GetType().Should().Be(typeof(SslHealthCheck));
        }

        [Fact]
        public void add_health_check_when_properly_configured_port()
        {
            var services = new ServiceCollection();
            services.AddHealthChecks()
                .AddSSLCertificate("host", port: 8081);

            var serviceProvider = services.BuildServiceProvider();
            var options = serviceProvider.GetService<IOptions<HealthCheckServiceOptions>>();

            var registration = options.Value.Registrations.First();
            var check = registration.Factory(serviceProvider);

            registration.Name.Should().Be("ssl_cert");
            check.GetType().Should().Be(typeof(SslHealthCheck));
        }

        [Fact]
        public void add_health_check_when_properly_configured_port_expire()
        {
            var services = new ServiceCollection();
            services.AddHealthChecks()
                .AddSSLCertificate("host", port: 8081, daysBeforeExpireDegraded: 180);

            var serviceProvider = services.BuildServiceProvider();
            var options = serviceProvider.GetService<IOptions<HealthCheckServiceOptions>>();

            var registration = options.Value.Registrations.First();
            var check = registration.Factory(serviceProvider);

            registration.Name.Should().Be("ssl_cert");
            check.GetType().Should().Be(typeof(SslHealthCheck));
        }

        [Fact]
        public void add_named_health_check_when_properly_configured()
        {
            var services = new ServiceCollection();
            services.AddHealthChecks()
                .AddSSLCertificate("host", name: "my-cert-1");

            var serviceProvider = services.BuildServiceProvider();
            var options = serviceProvider.GetService<IOptions<HealthCheckServiceOptions>>();

            var registration = options.Value.Registrations.First();
            var check = registration.Factory(serviceProvider);

            registration.Name.Should().Be("my-cert-1");
            check.GetType().Should().Be(typeof(SslHealthCheck));
        }

    }
}
