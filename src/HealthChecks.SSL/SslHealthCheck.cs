using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace HealthChecks.Ssl
{
    public class SslHealthCheck : IHealthCheck
    {
        private string _host;
        private int _port;
        private int _daysBeforeExpireDegraded;

        public SslHealthCheck(string host, int port, int daysBeforeExpireDegraded)
        {
            _host = host;
            _port = port;
            _daysBeforeExpireDegraded = daysBeforeExpireDegraded;
        }

        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return new HealthCheckResult(context.Registration.FailureStatus, description: $"{nameof(SslHealthCheck)} execution is cancelled.");
                }

                var crt = await GetSslCertificate(_host,_port);

                if (crt is null || !crt.Verify())
                {
                    return HealthCheckResult.Unhealthy();
                }

                if (crt.NotAfter.Subtract(DateTime.Now).TotalDays <= _daysBeforeExpireDegraded) return HealthCheckResult.Degraded();

                return HealthCheckResult.Healthy();
            }
            catch (System.Exception ex)
            {
                return new HealthCheckResult(context.Registration.FailureStatus, exception: ex);
            }
        }

        public async Task<X509Certificate2> GetSslCertificate(string host, int port)
        {

            using (TcpClient client = new TcpClient())
            {          
                await client.ConnectAsync(host, port);

                SslStream ssl = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback((sender, cert, ca, sslPolicyErrors) => sslPolicyErrors == SslPolicyErrors.None), null);
                
                try
                {
                    ssl.AuthenticateAsClient(host);
                    var cert = new X509Certificate2(ssl.RemoteCertificate);
                    ssl.Close();
                    client.Close();
                    return cert;
                }
                catch (Exception)
                {
                    ssl.Close();
                    client.Close();
                    return null;
                }
            }
        }
    }
}
