using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace VaultStore.Services
{
    public class Encryption
    {
        private readonly X509Certificate2 _certificate;

        public Encryption(X509Certificate2 certificate )
        {
            _certificate = certificate;
        }

        public byte[] Encrypt(byte[] data)
        {
            return EncryptDataOaepSha1(data);
        }
        
        public string Encrypt(string data)
        {
            var bytes = Encoding.Unicode.GetBytes(data);
            var encrypted =EncryptDataOaepSha1(bytes);
            return Encoding.Unicode.GetString(encrypted);
        }
        
        public string Decrypt(string data)
        {
            var bytes = Encoding.Unicode.GetBytes(data);
            var encrypted =DecryptDataOaepSha1(bytes);
            return Encoding.Unicode.GetString(encrypted);
        }

        public byte[] Decrypt(byte[] data)
        {
            return DecryptDataOaepSha1(data);
        }

        private byte[] EncryptDataOaepSha1(byte[] data)
        {
            using (RSA rsa = _certificate.GetRSAPublicKey())
            {
                return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA1);
            }
        }
        private byte[] DecryptDataOaepSha1(byte[] data)
        {
            using (RSA rsa = _certificate.GetRSAPrivateKey())
            {
                return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA1);
            }
        }

        public static X509Certificate2 IssueCertificate(string account, string key)
        {
            const string salt = "7hi5_i5_ju57_4_5417y_57ring";
            
            var ecdsa = ECDsa.Create(); // generate asymmetric key pair
            var req = new CertificateRequest($"cn={account}", ecdsa, HashAlgorithmName.SHA512);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));

            // Create PFX (PKCS #12) with private key
            var privateKey = cert.Export(X509ContentType.Pfx, salt+key);

            // Create Base 64 encoded CER (public key only)
            var base64Cer = 
                "-----BEGIN CERTIFICATE-----\r\n"
                + Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks)
                + "\r\n-----END CERTIFICATE-----";
            cert.Verify();
            return cert;
        } 
    }
}