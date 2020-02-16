using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using VaultStore.Filters;
using VaultStore.Services;
using System.Globalization;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using SampleApp.Utilities;

namespace VaultStore.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [ServiceFilter(typeof(CertificateFilter))]

    public class VaultDocumentController : ControllerBase
    {
     
        private readonly ILogger<WeatherForecastController> _logger;
        private readonly IConfiguration _config;
       
        private string _connectionString;

        public VaultDocumentController(ILogger<WeatherForecastController> logger, IConfiguration config)
        {
            _logger = logger;
            _config = config;
            _connectionString = _config.GetValue<string>("AzureStorageConnectionString");

        }
        
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> CreateContainer(string userName, string passwordHash)
        {
            var certificate=Encryption.IssueCertificate(userName,passwordHash);
            
            var encryption = new Encryption(certificate);
            var blobName = encryption.Encrypt(userName);
            
            
            var blobServiceClient = new BlobServiceClient(_connectionString);
            var containerClient = await blobServiceClient.CreateBlobContainerAsync(blobName);
            return Ok(
                new {
                Name=containerClient.Value.Name,
                Account=containerClient.Value.AccountName,
                Certificate=certificate.Export(X509ContentType.Cert, "5417"+passwordHash+"salt")
            });
        }
        
        [HttpPost]
        [DisableFormValueModelBinding]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UploadDatabase()
        {
            if (!MultipartRequestHelper.IsMultipartContentType(Request.ContentType))
            {
                ModelState.AddModelError("File", 
                    $"The request couldn't be processed (Error 1).");
                // Log error
                return BadRequest(ModelState);
            }
            
            // Accumulate the form data key-value pairs in the request (formAccumulator).
            var formAccumulator = new KeyValueAccumulator();
            var trustedFileNameForDisplay = string.Empty;
            var untrustedFileNameForStorage = string.Empty;
            var streamedFileContent = new byte[0];

            var bodyHeaders = MediaTypeHeaderValue.Parse(Request.ContentType);
            
            var boundary = HeaderUtilities.RemoveQuotes(bodyHeaders.Boundary.Value).Value;

            var reader = new MultipartReader(boundary, HttpContext.Request.Body);
            var section = await reader.ReadNextSectionAsync();

            while (section != null)
            {
                var hasContentDispositionHeader = ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out var contentDisposition);

                if (hasContentDispositionHeader)
                {
                    if (MultipartRequestHelper.HasFileContentDisposition(contentDisposition))
                    {
                        untrustedFileNameForStorage = contentDisposition.FileName.Value;
                        // Don't trust the file name sent by the client. To display
                        // the file name, HTML-encode the value.
                        trustedFileNameForDisplay = WebUtility.HtmlEncode(contentDisposition.FileName.Value);

                        streamedFileContent = await FileHelpers.ProcessStreamedFile(section, contentDisposition, 
                                ModelState, FileHelpers._fileSignature.Keys.ToArray());

                        if (!ModelState.IsValid)
                        {
                            return BadRequest(ModelState);
                        }
                    }
                    else if (MultipartRequestHelper.HasFormDataContentDisposition(contentDisposition))
                    {
                        // Don't limit the key name length because the 
                        // multipart headers length limit is already in effect.
                        var key = HeaderUtilities.RemoveQuotes(contentDisposition.Name).Value;
                        
                        var encoding = GetEncoding(section);

                        if (encoding == null)
                        {
                            ModelState.AddModelError("File", $"The request couldn't be processed (Error 2).");
                            // Log error

                            return BadRequest(ModelState);
                        }

                        using (var streamReader = new StreamReader(section.Body,encoding, true,1024, true))
                        {
                            // The value length limit is enforced by MultipartBodyLengthLimit
                            var value = await streamReader.ReadToEndAsync();

                            if (string.Equals(value, "undefined", StringComparison.OrdinalIgnoreCase))
                            {
                                value = string.Empty;
                            }

                            formAccumulator.Append(key, value);
                        }
                    }
                }

                // Drain any remaining section body that hasn't been consumed and
                // read the headers for the next section.
                section = await reader.ReadNextSectionAsync();
            }

            // Bind form data to the model
            var formData = new FormData();
            var formValueProvider = new FormValueProvider(BindingSource.Form, new FormCollection(formAccumulator.GetResults()), CultureInfo.CurrentCulture);
            var bindingSuccessful = await TryUpdateModelAsync(formData, prefix: "", valueProvider: formValueProvider);

            if (!bindingSuccessful)
            {
                ModelState.AddModelError("File", "The request couldn't be processed (Error 5).");
                // Log error
                return BadRequest(ModelState);
            }

            
            var certificate = CertificateFilter.GetFromHeader(ControllerContext.HttpContext);
            var blobServiceClient = new BlobServiceClient(_connectionString);
            
            var encryption = new Encryption(certificate);
            var blobName = encryption.Encrypt(userName);
            var containerClient = blobServiceClient.GetBlobContainerClient(blobName);
            //if (this.Request.IsMimeMultipartContent())

            
            
            var file = new AppFile()
            {
                Content = streamedFileContent,
                UntrustedName = untrustedFileNameForStorage,
            };

            _context.File.Add(file);
            await _context.SaveChangesAsync();

            return Created(nameof(StreamingController), null);
        }

        [HttpGet]
        public IEnumerable<WeatherForecast> Get()
        {
            var rng = new Random();
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
                {
                    Date = DateTime.Now.AddDays(index),
                    TemperatureC = rng.Next(-20, 55),
                    Summary = Summaries[rng.Next(Summaries.Length)]
                })
                .ToArray();
        }
        
        private static Encoding GetEncoding(MultipartSection section)
        {
            var hasMediaTypeHeader = 
                MediaTypeHeaderValue.TryParse(section.ContentType, out var mediaType);

            // UTF-7 is insecure and shouldn't be honored. UTF-8 succeeds in 
            // most cases.
            if (!hasMediaTypeHeader || Encoding.UTF7.Equals(mediaType.Encoding))
            {
                return Encoding.UTF8;
            }

            return mediaType.Encoding;
        }
    }
    public class FormData
    {
        public string Note { get; set; }
    }
}