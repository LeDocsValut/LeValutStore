using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Filters;

namespace VaultStore.Filters
{
    public class CertificateFilter : IAsyncActionFilter
    {
        private const string EncryptionHeader="X-EncryptCert";
        private const string CertificateHeader="Certificate";
        
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            X509Certificate2 clientCertificate = null;
            if(context.HttpContext.Items.TryGetValue(EncryptionHeader, out var value))
            {
                byte[] bytes = StringToByteArray(value.ToString());
                clientCertificate = new X509Certificate2(bytes);
                context.HttpContext.Items.Add(CertificateHeader,clientCertificate);
            }

            await next();
        }

        public static X509Certificate2 GetFromHeader(HttpContext context)
        {
            context.Items.TryGetValue(CertificateFilter.CertificateHeader, out var certificate);

            return certificate as X509Certificate2;
        } 
        
        private static byte[] StringToByteArray(string hex)
        {
            var numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];

            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }
    }
}