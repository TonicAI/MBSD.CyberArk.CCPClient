/*
 * Copyright 2025 Matthew Bohan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * DISCLAIMER: This library is developed independently by Matthew Bohan and is not
 * affiliated with, endorsed by, or sponsored by CyberArk / CyberArk Software Ltd.
 * CyberArk® and related names are property of CyberArk Software Ltd. or its affiliates.
 */

using MBSD.CyberArk.CCPClient.Configuration;
using MBSD.CyberArk.CCPClient.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.Security;

namespace MBSD.CyberArk.CCPClient
{
    /// <summary>
    /// CyberArk Central Credential Provider (CCP) client implementation
    /// </summary>


    [SuppressMessage("StyleCop.CSharp.NamingRules", "S101:Type name should comply with naming convention",
        Justification = "CCPClient represents a CyberArk Central Credential Provider client so the capitalisation makes sense")]

    [SuppressMessage("Security", "S4830:Server certificate validation should not be disabled",
        Justification = "Certificate validation can be disabled through configuration for testing/development environments. A warning is generated at runtime.")]

    public class CCPClient : ICCPClient
    {
        private static readonly string UserAgent =
            $"MBSD-CyberArk-CCPClient/{typeof(CCPClient).Assembly.GetName().Version.ToString(3)}";

        private readonly HttpClient _defaultHttpClient;
        private readonly CCPOptions _options;
        private readonly ILogger _logger;
        private readonly Func<X509Certificate2, HttpMessageHandler> _certificateHandlerFactory;
        private readonly Dictionary<string, CertificateHttpClient> _certificateHttpClients = new Dictionary<string, CertificateHttpClient>();
        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the CcpClient
        /// </summary>
        /// <param name="httpClient">Default HTTP client (for non-certificate requests)</param>
        /// <param name="options">CCP configuration options</param>
        /// <param name="logger">Logger instance</param>
        /// <param name="certificateHandlerFactory">
        /// Optional. Builds the HTTP handler for certificate-authenticated requests, given the client certificate the request
        /// authenticates with. The handler must attach that certificate and verify the server's certificate itself:
        /// <see cref="CCPOptions.VerifySsl"/> does not apply to it. The client still sets the base address, timeout and
        /// User-Agent on the <see cref="HttpClient"/> it wraps the handler in, and disposes the handler and the certificate when
        /// it is disposed. When not set, the client builds an <see cref="HttpClientHandler"/> itself.
        /// </param>
        public CCPClient(
            HttpClient httpClient,
            IOptions<CCPOptions> options,
            ILogger logger = null,
            Func<X509Certificate2, HttpMessageHandler> certificateHandlerFactory = null)
        {
            _defaultHttpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<CCPClient>.Instance;
            _certificateHandlerFactory = certificateHandlerFactory;

            _options.Validate();
        }

        /// <summary>
        /// Retrieves a secret from CCP
        /// </summary>
        public async Task<CCPSecret> GetSecretAsync(SecretRequest request, CancellationToken cancellationToken = default)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));

            var applicationId = GetEffectiveApplicationId(request);
            if (string.IsNullOrWhiteSpace(applicationId))
                throw new ArgumentException("Application ID must be specified either in request or in options.DefaultApplicationId");

            try
            {
                _logger.LogDebug("Retrieving secret for object: {Object} using Application ID: {ApplicationId}",
                    request.FullIdentifier(), applicationId);

                var httpClient = GetHttpClientForRequest(request);
                var queryString = BuildQueryString(request, applicationId);
                var requestUri = $"{_options.BaseUrl.TrimEnd('/')}{_options.Endpoint}?{queryString}";

                _logger.LogDebug("Making CCP request to: {RequestUri}", SanitizeUriForLogging(requestUri));

                var uri = new Uri(requestUri, UriKind.Absolute);

                // The timeout covers reading the body too: HttpClient.Timeout stops at the headers when the body is streamed.
                using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    timeout.CancelAfter(TimeSpan.FromSeconds(_options.TimeoutSeconds));
                    using (var response = await httpClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
                               .ConfigureAwait(false))
                    {
                        var content = await ReadContentAsync(response, applicationId, timeout.Token).ConfigureAwait(false);

                        if (!response.IsSuccessStatusCode)
                        {
                            // The body is not logged: it comes from the server and can echo back the request.
                            _logger.LogError("CCP request failed with status {StatusCode}", response.StatusCode);

                            throw new CCPException(
                                $"Failed to retrieve secret '{request.FullIdentifier()}' using Application ID '{applicationId}'. Status: {response.StatusCode}",
                                httpStatusCode: (int)response.StatusCode,
                                responseContent: content,
                                applicationId: applicationId);
                        }

                        _logger.LogDebug("CCP response received successfully for object: {Object}", request.FullIdentifier());

                        var ccpSecret = JsonConvert.DeserializeObject<CCPSecret>(content);

                        if (ccpSecret == null)
                        {
                            throw new CCPException($"Failed to deserialize CCP response for object '{request.FullIdentifier()}'",
                                applicationId: applicationId);
                        }

                        _logger.LogDebug("Successfully retrieved secret for object: {Object}, Application ID: {ApplicationId}",
                            request.FullIdentifier(), applicationId);

                        return ccpSecret;
                    }
                }
            }
            catch (Exception ex) when (ex is HttpRequestException || ex is IOException)
            {
                _logger.LogError(ex, "HTTP request exception while retrieving secret for object: {Object}", request.FullIdentifier());
                throw new CCPException($"Network error while retrieving secret '{request.FullIdentifier()}'", ex, applicationId: applicationId);
            }
            catch (OperationCanceledException ex) when (cancellationToken.IsCancellationRequested)
            {
                _logger.LogError(ex, "Request cancelled while retrieving secret for object: {Object}", request.FullIdentifier());
                throw new CCPException($"Request cancelled while retrieving secret '{request.FullIdentifier()}'", ex, applicationId: applicationId);
            }
            catch (OperationCanceledException ex)
            {
                _logger.LogError(ex, "Request timeout while retrieving secret for object: {Object}", request.FullIdentifier());
                throw new CCPException($"Request timeout while retrieving secret '{request.FullIdentifier()}'", ex, applicationId: applicationId);
            }
        }

        /// <summary>
        /// Retrieves a secret by object name using default Application ID, SafeName and object name - which is the recommended efficient way of retrieving CCP secrets
        /// </summary>
        public async Task<CCPSecret> GetSecretAsync(string applicationId, string safeName, string objectName, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(objectName))
                throw new ArgumentException("Object name cannot be null or empty", nameof(objectName));

            var request = SecretRequest
                                       .ForObject(objectName)
                                       .UsingApplicationId(applicationId)
                                       .InSafe(safeName);


            return await GetSecretAsync(request, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Retrieves only the password content by object name
        /// </summary>
        public async Task<string> GetPasswordOnlyAsync(string applicationId, string safeName, string objectName, CancellationToken cancellationToken = default)
        {
            var secret = await GetSecretAsync(applicationId, safeName, objectName, cancellationToken).ConfigureAwait(false);
            return secret.Content;
        }

        /// <summary>
        /// Retrieves only the password content
        /// </summary>
        public async Task<string> GetPasswordOnlyAsync(SecretRequest request, CancellationToken cancellationToken = default)
        {
            var secret = await GetSecretAsync(request, cancellationToken).ConfigureAwait(false);
            return secret.Content;
        }

        /// <summary>
        /// Tests the connection to CyberArk CCP using default Application ID
        /// </summary>
        public async Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(_options.DefaultApplicationId))
            {
                _logger.LogWarning("Cannot test connection: no default Application ID configured");
                return false;
            }

            try
            {
                _logger.LogDebug("Testing connection to CyberArk CCP");

                var testUri =
                    $"{_options.BaseUrl.TrimEnd('/')}{_options.Endpoint}?{QueryParameter("AppID", _options.DefaultApplicationId)}&Object=test";

                using (var response = await _defaultHttpClient
                           .GetAsync(new Uri(testUri, UriKind.Absolute), HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                           .ConfigureAwait(false))
                {
                    var isConnected = response.StatusCode != System.Net.HttpStatusCode.ServiceUnavailable &&
                                      response.StatusCode != System.Net.HttpStatusCode.BadGateway &&
                                      response.StatusCode != System.Net.HttpStatusCode.GatewayTimeout;

                    _logger.LogDebug("Connection test result: {IsConnected} (Status: {StatusCode})",
                        isConnected, response.StatusCode);

                    return isConnected;
                }
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "Connection test failed due to network error");
                return false;
            }
            catch (TaskCanceledException ex) when (ex.CancellationToken == cancellationToken)
            {
                _logger.LogError(ex, "Connection test cancelled");
                return false;
            }
            catch (TaskCanceledException ex)
            {
                _logger.LogError(ex, "Connection test timeout");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during connection test");
                return false;
            }
        }

        #region Synchronous Methods

        /// <summary>
        /// Retrieves a secret from CCP (synchronous)
        /// </summary>
        public CCPSecret GetSecret(SecretRequest request)
        {
            return GetSecretAsync(request).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Retrieves a secret by application id, safe name and object name (the recommended efficient way of retrieving CCP secrets  (synchronous)
        /// </summary>
        public CCPSecret GetSecret(string applicationId, string safeName, string objectName)
        {
            return GetSecretAsync(applicationId, safeName, objectName).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Retrieves only the password content by object name (synchronous)
        /// </summary>
        public string GetPasswordOnly(string applicationId, string safeName, string objectName)
        {
            return GetPasswordOnlyAsync(applicationId, safeName, objectName).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Retrieves only the password content (synchronous)
        /// </summary>
        public string GetPasswordOnly(SecretRequest request)
        {
            return GetPasswordOnlyAsync(request).ConfigureAwait(false).GetAwaiter().GetResult();
        }



        /// <summary>
        /// Tests the connection to CyberArk CCP (synchronous)
        /// </summary>
        public bool TestConnection()
        {
            return TestConnectionAsync().ConfigureAwait(false).GetAwaiter().GetResult();
        }

        #endregion

        /// <summary>
        /// Gets the effective Application ID for a request
        /// </summary>
        private string GetEffectiveApplicationId(SecretRequest request)
        {
            return !string.IsNullOrWhiteSpace(request.ApplicationId)
                ? request.ApplicationId
                : _options.DefaultApplicationId;
        }

        /// <summary>
        /// Gets the effective certificate configuration for a request
        /// </summary>
        private CertificateConfig GetEffectiveCertificateConfig(SecretRequest request)
        {
            // 1. Request-specific certificate takes precedence
            if (request.Certificate?.IsConfigured == true)
                return request.Certificate;

            // 2. Application ID-specific certificate
            var applicationId = GetEffectiveApplicationId(request);
            if (!string.IsNullOrWhiteSpace(applicationId) &&
                _options.CertificatesByApplicationId.TryGetValue(applicationId, out var appIdCert) &&
                appIdCert.IsConfigured)
                return appIdCert;

            // 3. Default certificate
            if (_options.DefaultCertificate.IsConfigured)
                return _options.DefaultCertificate;

            return null;
        }

        /// <summary>
        /// Gets the appropriate HTTP client for the request (with certificate if needed)
        /// </summary>
        private HttpClient GetHttpClientForRequest(SecretRequest request)
        {
            var certificateConfig = GetEffectiveCertificateConfig(request);

            if (certificateConfig == null)
            {
                return _defaultHttpClient;
            }

            var cacheKey = GetCertificateCacheKey(certificateConfig);

            // A lock rather than ConcurrentDictionary.GetOrAdd: GetOrAdd can run the factory twice under contention and drop
            // one result, which would leak its client and certificate. Building a client is rare, so the lock is uncontended.
            lock (_certificateHttpClients)
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(nameof(CCPClient));
                }

                if (!_certificateHttpClients.TryGetValue(cacheKey, out var certificateHttpClient))
                {
                    certificateHttpClient = CreateCertificateHttpClient(certificateConfig);
                    _certificateHttpClients.Add(cacheKey, certificateHttpClient);
                }

                return certificateHttpClient.Client;
            }
        }

        /// <summary>
        /// Creates a cache key for certificate configuration
        /// </summary>
        /// <remarks>
        /// File and binary keys hash the material the certificate is loaded from together with its password. Keying on the
        /// certificate's thumbprint instead would let a certificate-only file that copies another caller's public certificate
        /// reuse the cached client that holds that caller's private key; keying without the password would let a wrong password
        /// reuse a client loaded with the right one.
        /// </remarks>
        private static string GetCertificateCacheKey(CertificateConfig config)
        {
            switch (config.Source)
            {
                case CertificateSource.File:
                    return $"file:{Hash(Encoding.UTF8.GetBytes(config.FilePath), config.Password)}";
                case CertificateSource.Store:
                    return $"store:{config.Thumbprint}:{config.StoreLocation}:{config.StoreName}";
                case CertificateSource.Binary:
                    return $"binary:{Hash(config.BinaryCertificate, config.Password)}";
                case CertificateSource.None:
                default:
                    throw new ArgumentOutOfRangeException($"Unexpected certificate source {nameof(config.Source)}");

            }
        }

        /// <summary>
        /// Hashes certificate material and its password with SHA-256, length-prefixing the material so that no two distinct
        /// pairs produce the same input.
        /// </summary>
        private static string Hash(byte[] material, string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var length = BitConverter.GetBytes(material.Length);
                var passwordBytes = Encoding.UTF8.GetBytes(password ?? string.Empty);
                sha256.TransformBlock(length, 0, length.Length, null, 0);
                sha256.TransformBlock(material, 0, material.Length, null, 0);
                sha256.TransformFinalBlock(passwordBytes, 0, passwordBytes.Length);
                return BitConverter.ToString(sha256.Hash).Replace("-", string.Empty);
            }
        }

        /// <summary>
        /// Creates an HTTP client that authenticates with the specified certificate
        /// </summary>
        private CertificateHttpClient CreateCertificateHttpClient(CertificateConfig certificateConfig)
        {
            X509Certificate2 certificate;
            try
            {
                certificate = LoadCertificate(certificateConfig);
            }
            catch (CCPException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new CCPException($"Failed to load certificate: {ex.Message}", ex);
            }

            try
            {
                if (!certificate.HasPrivateKey)
                {
                    throw new CCPException("The client certificate has no private key, so it cannot be used to authenticate to CCP");
                }

                var handler = _certificateHandlerFactory != null
                    ? _certificateHandlerFactory(certificate)
                      ?? throw new InvalidOperationException("The certificate handler factory returned no handler")
                    : CreateDefaultCertificateHandler(certificate);

                var client = new HttpClient(handler)
                {
                    BaseAddress = new Uri(_options.BaseUrl),
                    Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds),
                };
                client.DefaultRequestHeaders.Add("User-Agent", UserAgent);

                _logger.LogDebug("Created HTTP client with certificate: {CertificateSubject}", certificate.Subject);

                return new CertificateHttpClient(client, certificate);
            }
            catch
            {
                certificate.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Creates the handler used for certificate authentication when the caller supplies no handler factory
        /// </summary>
        private HttpClientHandler CreateDefaultCertificateHandler(X509Certificate2 certificate)
        {
            var handler = new HttpClientHandler();

            if (!_options.VerifySsl)
            {
                 _logger.LogWarning("SSL certificate verification is disabled. This exposes you to security risks and is not recommended for use in production.");
            }

            handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
            {
                if (!_options.VerifySsl || sslPolicyErrors == SslPolicyErrors.None)
                {
                    return true;
                }

                if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
                {
                    _logger.LogDebug("Certificate name mismatch. Subject: {Subject}", cert.Subject);

                    // Extract Subject Alternative Names (SANs)
                    var sanExtension = cert.Extensions
                        .OfType<X509Extension>()
                        .FirstOrDefault(ext => ext.Oid.FriendlyName == "Subject Alternative Name");

                    if (sanExtension == null) return false;
                    var asndata = new AsnEncodedData(sanExtension.RawData);
                    var sans = asndata.Format(true);
                    _logger.LogDebug("Subject Alternative Names: {SubjectAlternativeNames}", sans);
                    // The formatted output might be a single string with multiple entries separated by newlines or commas
                }
                return false;
            };

            handler.ClientCertificates.Add(certificate);
            return handler;
        }

        /// <summary>
        /// Loads a certificate based on configuration
        /// </summary>
        private static X509Certificate2 LoadCertificate(CertificateConfig config)
        {
            switch (config.Source)
            {
                case CertificateSource.File:
                    return !string.IsNullOrWhiteSpace(config.Password)
                        ? new X509Certificate2(config.FilePath, config.Password)
                        : new X509Certificate2(config.FilePath);

                case CertificateSource.Store:
                {
                    var store = new X509Store(config.StoreName, config.StoreLocation);
                    try
                    {
                        store.Open(OpenFlags.ReadOnly);

                        var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, config.Thumbprint, false);

                        if (certificates.Count == 0)
                        {
                            throw new CCPException(
                                $"Certificate with thumbprint '{config.Thumbprint}' not found in store '{config.StoreName}' at location '{config.StoreLocation}'");
                        }

                        return certificates[0];
                    }
                    finally
                    {
                        store.Dispose();
                    }
                }

                case CertificateSource.Binary:
                    return !string.IsNullOrWhiteSpace(config.Password)
                        ? new X509Certificate2(config.BinaryCertificate, config.Password)
                        : new X509Certificate2(config.BinaryCertificate);

                case CertificateSource.None:
                default:
                    throw new ArgumentOutOfRangeException($"Unexpected certificate source {nameof(config.Source)}");
            }
        }

        /// <summary>
        /// Reads the response body as a string, refusing a body larger than <see cref="CCPOptions.MaxResponseContentBytes"/>
        /// </summary>
        private async Task<string> ReadContentAsync(HttpResponseMessage response, string applicationId, CancellationToken cancellationToken)
        {
            if (response.Content == null)
            {
                return string.Empty;
            }

            var limit = _options.MaxResponseContentBytes;
            if (response.Content.Headers.ContentLength > limit)
            {
                throw ResponseTooLarge(response, applicationId);
            }

            using (var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
            using (var buffer = new MemoryStream())
            {
                var chunk = new byte[8192];
                int read;
                while ((read = await stream.ReadAsync(chunk, 0, chunk.Length, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    if (buffer.Length + read > limit)
                    {
                        throw ResponseTooLarge(response, applicationId);
                    }

                    buffer.Write(chunk, 0, read);
                }

                buffer.Position = 0;
                using (var reader = new StreamReader(buffer, GetEncoding(response.Content), detectEncodingFromByteOrderMarks: true))
                {
                    return await reader.ReadToEndAsync().ConfigureAwait(false);
                }
            }
        }

        private CCPException ResponseTooLarge(HttpResponseMessage response, string applicationId) =>
            new CCPException(
                $"The CCP response is larger than the {_options.MaxResponseContentBytes}-byte limit. Status: {response.StatusCode}",
                httpStatusCode: (int)response.StatusCode,
                applicationId: applicationId);

        private static Encoding GetEncoding(HttpContent content)
        {
            var charset = content.Headers.ContentType?.CharSet;
            if (string.IsNullOrWhiteSpace(charset))
            {
                return Encoding.UTF8;
            }

            try
            {
                return Encoding.GetEncoding(charset.Trim('"'));
            }
            catch (ArgumentException)
            {
                return Encoding.UTF8;
            }
        }

        /// <summary>
        /// Builds the query string for CCP requests
        /// </summary>
        /// <remarks>
        /// Every name and value is percent-escaped, so a <c>#</c>, <c>&amp;</c> or <c>%</c> in a value cannot end it early or
        /// add a parameter, and a space is sent as <c>%20</c> (not <c>+</c>, which CCP reads as a literal plus sign).
        /// </remarks>
        private static string BuildQueryString(SecretRequest request, string applicationId)
        {
            var parameters = new List<string>
            {
                QueryParameter("AppID", applicationId),
            };

            if (!string.IsNullOrWhiteSpace(request.Object))
                parameters.Add(QueryParameter("Object", request.Object));

            if (!string.IsNullOrWhiteSpace(request.Safe))
                parameters.Add(QueryParameter("Safe", request.Safe));

            if (!string.IsNullOrWhiteSpace(request.Folder))
                parameters.Add(QueryParameter("Folder", request.Folder));

            if (!string.IsNullOrWhiteSpace(request.UserName))
                parameters.Add(QueryParameter("UserName", request.UserName));

            if (!string.IsNullOrWhiteSpace(request.Address))
                parameters.Add(QueryParameter("Address", request.Address));

            if (!string.IsNullOrWhiteSpace(request.Database))
                parameters.Add(QueryParameter("Database", request.Database));

            if (!string.IsNullOrWhiteSpace(request.PolicyID))
                parameters.Add(QueryParameter("PolicyID", request.PolicyID));

            foreach (var param in request.CustomParameters)
            {
                if (!string.IsNullOrWhiteSpace(param.Key) && param.Value != null)
                {
                    parameters.Add(QueryParameter(param.Key, param.Value));
                }
            }

            return string.Join("&", parameters);
        }

        private static string QueryParameter(string name, string value) => $"{Uri.EscapeDataString(name)}={Uri.EscapeDataString(value)}";

        /// <summary>
        /// Sanitizes URI for logging by removing sensitive parameters
        /// </summary>
        private static string SanitizeUriForLogging(string uri)
        {
            try
            {
                var uriObj = new Uri(uri);
                return $"{uriObj.Scheme}://{uriObj.Host}{uriObj.PathAndQuery.Split('?')[0]}?[QUERY_PARAMETERS]";
            }
            catch
            {
                return "[Invalid URI]";
            }
        }

        /// <summary>
        /// Disposes the client and all cached HTTP clients
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            lock (_certificateHttpClients)
            {
                if (_disposed)
                {
                    return;
                }

                foreach (var certificateHttpClient in _certificateHttpClients.Values)
                {
                    try
                    {
                        certificateHttpClient.Dispose();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error disposing certificate HTTP client");
                    }
                }

                _certificateHttpClients.Clear();
                _disposed = true;
            }
        }

        /// <summary>
        /// Disposes the CCPClient instance.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// A cached certificate-authenticated client and the certificate it authenticates with, disposed together
        /// </summary>
        private sealed class CertificateHttpClient : IDisposable
        {
            private readonly X509Certificate2 _certificate;

            public CertificateHttpClient(HttpClient client, X509Certificate2 certificate)
            {
                Client = client;
                _certificate = certificate;
            }

            public HttpClient Client { get; }

            public void Dispose()
            {
                try
                {
                    Client.Dispose();
                }
                finally
                {
                    _certificate.Dispose();
                }
            }
        }
    }
}
