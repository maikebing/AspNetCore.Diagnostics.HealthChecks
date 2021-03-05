using FluentAssertions;
using FunctionalTests.Base;
using FunctionalTests.HealthChecks.Publisher.Prometheus;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace FunctionalTests.HealthChecks.Ssl
{
    //For testing certificates the code use badssl.com web site, witch provide samples certificates with varius states and types 
    [Collection("execution")]
    public class ssl_healthcheck_should
    {
        
        private readonly ExecutionFixture _fixture;

        public ssl_healthcheck_should(ExecutionFixture fixture)
        {
            _fixture = fixture ?? throw new ArgumentNullException(nameof(fixture));
        }

        [Fact]
        public async Task be_healthy_if_ssl_is_valid()
        {
            var host = "sha256.badssl.com";

            var webHostBuilder = new WebHostBuilder()
               .UseStartup<DefaultStartup>()
               .ConfigureServices(services =>
               {
                   services.AddHealthChecks()
                    .AddSSLCertificate(host, tags: new string[] { "ssl" });
               })
               .Configure(app =>
               {
                   app.UseHealthChecks("/health", new HealthCheckOptions()
                   {
                       Predicate = r => r.Tags.Contains("ssl")
                   });
               });

            var server = new TestServer(webHostBuilder);

            var response = await server.CreateRequest($"/health").GetAsync();

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task be_unhealthy_if_ssl_is_not_present()
        {
            var host = "www.uffweb.it";

            var webHostBuilder = new WebHostBuilder()
               .UseStartup<DefaultStartup>()
               .ConfigureServices(services =>
               {
                   services.AddHealthChecks()
                    .AddSSLCertificate(host, tags: new string[] { "ssl" });
               })
               .Configure(app =>
               {
                   app.UseHealthChecks("/health", new HealthCheckOptions()
                   {
                       Predicate = r => r.Tags.Contains("ssl")
                   });
               });

            var server = new TestServer(webHostBuilder);

            var response = await server.CreateRequest($"/health").GetAsync();

            response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        }
        
        [Fact]
        public async Task be_unhealthy_if_ssl_is_not_valid()
        {
            var host = "revoked.badssl.com";

            var webHostBuilder = new WebHostBuilder()
               .UseStartup<DefaultStartup>()
               .ConfigureServices(services =>
               {
                   services.AddHealthChecks()
                    .AddSSLCertificate(host, tags: new string[] { "ssl" });
               })
               .Configure(app =>
               {
                   app.UseHealthChecks("/health", new HealthCheckOptions()
                   {
                       Predicate = r => r.Tags.Contains("ssl")
                   });
               });

            var server = new TestServer(webHostBuilder);

            var response = await server.CreateRequest($"/health").GetAsync();

            response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        }

        [Fact]
        public async Task be_unhealthy_if_ssl_is_expired()
        {
            var host = "expired.badssl.com";

            var webHostBuilder = new WebHostBuilder()
               .UseStartup<DefaultStartup>()
               .ConfigureServices(services =>
               {
                   services.AddHealthChecks()
                    .AddSSLCertificate(host, tags: new string[] { "ssl" });
               })
               .Configure(app =>
               {
                   app.UseHealthChecks("/health", new HealthCheckOptions()
                   {
                       Predicate = r => r.Tags.Contains("ssl")
                   });
               });

            var server = new TestServer(webHostBuilder);

            var response = await server.CreateRequest($"/health").GetAsync();

            response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        }

        [Fact]
        public async Task be_degraded_if_ssl_daysbefore()
        {
            var host = "sha256.badssl.com";

            var webHostBuilder = new WebHostBuilder()
               .UseStartup<DefaultStartup>()
               .ConfigureServices(services =>
               {
                   services.AddHealthChecks()
                    .AddSSLCertificate(host,daysBeforeExpireDegraded:1095, tags: new string[] { "ssl" });
               })
               .Configure(app =>
               {
                   app.UseHealthChecks("/health", new HealthCheckOptions()
                   {
                       Predicate = r => r.Tags.Contains("ssl")
                   });
               });

            var server = new TestServer(webHostBuilder);

            var response = await server.CreateRequest($"/health").GetAsync();

            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var resultAsString = await response.Content.ReadAsStringAsync();
            resultAsString.Should().Contain(HealthStatus.Degraded.ToString());
        }

        [Fact]
        public async Task be_unhealthy_if_host_not_found()
        {
            var host = "notfoundhost.domain.no";

            var webHostBuilder = new WebHostBuilder()
               .UseStartup<DefaultStartup>()
               .ConfigureServices(services =>
               {
                   services.AddHealthChecks()
                    .AddSSLCertificate(host, tags: new string[] { "ssl" });
               })
               .Configure(app =>
               {
                   app.UseHealthChecks("/health", new HealthCheckOptions()
                   {
                       Predicate = r => r.Tags.Contains("ssl")
                   });
               });

            var server = new TestServer(webHostBuilder);

            var response = await server.CreateRequest($"/health").GetAsync();

            response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        }

        [Fact]
        public async Task be_unhealthy_if_port_not_found()
        {
            var host = "sha256.badssl.com";

            var webHostBuilder = new WebHostBuilder()
               .UseStartup<DefaultStartup>()
               .ConfigureServices(services =>
               {
                   services.AddHealthChecks()
                    .AddSSLCertificate(host, port: 10000, tags: new string[] { "ssl" });
               })
               .Configure(app =>
               {
                   app.UseHealthChecks("/health", new HealthCheckOptions()
                   {
                       Predicate = r => r.Tags.Contains("ssl")
                   });
               });

            var server = new TestServer(webHostBuilder);

            var response = await server.CreateRequest($"/health").GetAsync();

            response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        }
    }

}
