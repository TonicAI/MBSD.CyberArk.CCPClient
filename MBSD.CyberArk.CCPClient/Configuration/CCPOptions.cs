using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace MBSD.CyberArk.CCPClient.Configuration
{
    /// <summary>
    /// Configuration options for CyberArk Central Credential Provider (CCP)
    /// </summary>
    public class CCPOptions
    {
        /// <summary>
        /// Base URL for the CyberArk CCP server (e.g., https://ccp.company.com)
        /// </summary>
        public string BaseUrl { get; set; } = string.Empty;

        /// <summary>
        /// Default Application ID for CCP authentication (can be overridden per request)
        /// </summary>
        public string DefaultApplicationId { get; set; } = string.Empty;

        /// <summary>
        /// CCP endpoint path (default: /AIMWebService/api/Accounts)
        /// </summary>
        public string Endpoint { get; set; } = "/AIMWebService/api/Accounts";

        /// <summary>
        /// Connection timeout in seconds (default: 30)
        /// </summary>
        public int TimeoutSeconds { get; set; } = 30;

        /// <summary>
        /// Whether to verify SSL certificates (default: true)
        /// </summary>
        public bool VerifySsl { get; set; } = true;

        /// <summary>
        /// Default client certificate configuration (can be overridden per request)
        /// </summary>
        public CertificateConfig DefaultCertificate { get; set; } = new CertificateConfig();

        /// <summary>
        /// Pre-configured certificates for different Application IDs
        /// </summary>
        public Dictionary<string, CertificateConfig> CertificatesByApplicationId { get; set; } = new Dictionary<string, CertificateConfig>();

        /// <summary>
        /// Validates the configuration options
        /// </summary>
        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(BaseUrl))
                throw new ArgumentException("BaseUrl is required", nameof(BaseUrl));

            // Application ID is now optional at the client level since it can be provided per request
            
            // Validate default certificate if configured
            if (DefaultCertificate.IsConfigured)
                DefaultCertificate.Validate();

            // Validate all pre-configured certificates
            foreach (var cert in CertificatesByApplicationId.Values)
            {
                if (cert.IsConfigured)
                    cert.Validate();
            }
        }
    }

    /// <summary>
    /// Certificate source
    /// </summary>
    public enum CertificateSource
    {
        /// <summary>
        /// No source specified
        /// </summary>
        None,
        
        /// <summary>
        /// Certificate comes from external file
        /// </summary>
        File,
        
        /// <summary>
        /// Certificate comes from certificate store via thumbprint
        /// </summary>
        Store,
        
        /// <summary>
        /// Certificate is provided in binary format 
        /// </summary>
        Binary,
    }

    /// <summary>
    /// Certificate configuration for client authentication
    /// </summary>
    public class CertificateConfig
    {
        /// <summary>
        /// Identifies the source of the certificate
        /// </summary>
        public CertificateSource Source = CertificateSource.None;
        
        #region Certificate file
        /// <summary>
        /// Client certificate path for certificate-based authentication
        /// </summary>
        public string FilePath { get; set; } = string.Empty;

        /// <summary>
        /// Client certificate password
        /// </summary>
        public string Password { get; set; } = string.Empty;
        #endregion

        #region Certificate store
        /// <summary>
        /// Client certificate thumbprint (for loading from certificate store)
        /// </summary>
        public string Thumbprint { get; set; } = string.Empty;

        /// <summary>
        /// Certificate store location (default: CurrentUser)
        /// </summary>
        public StoreLocation StoreLocation { get; set; } = StoreLocation.CurrentUser;

        /// <summary>
        /// Certificate store name (default: My)
        /// </summary>
        public StoreName StoreName { get; set; } = StoreName.My;
        #endregion
        
        #region Binary certificate
        /// <summary>
        /// Binary certificate (default: empty array)
        /// </summary>
        public byte[] BinaryCertificate = Array.Empty<byte>();
        #endregion
        
        /// <summary>
        /// Indicates whether certificate authentication is configured
        /// </summary>
        public bool IsConfigured => Source != CertificateSource.None;

        /// <summary>
        /// Validates the certificate configuration
        /// </summary>
        public void Validate()
        {
            switch (Source)
            {
                case CertificateSource.File:
                    if (string.IsNullOrWhiteSpace(FilePath))
                    {
                        throw new ArgumentException("FilePath is required", nameof(FilePath));
                    }

                    if (!string.IsNullOrWhiteSpace(Thumbprint) ||
                        (BinaryCertificate != null && BinaryCertificate.Length > 0))
                    {
                        throw new ArgumentException("Cannot specify multiple sources", nameof(FilePath));
                    }
                    break;
                case CertificateSource.Store:
                    if (string.IsNullOrWhiteSpace(Thumbprint))
                    {
                        throw new ArgumentException("Thumbprint is required", nameof(Thumbprint));
                    }
                    if (!string.IsNullOrWhiteSpace(FilePath) ||
                        (BinaryCertificate != null && BinaryCertificate.Length > 0))
                    {
                        throw new ArgumentException("Cannot specify multiple sources", nameof(Thumbprint));
                    }
                    break;
                case CertificateSource.Binary:
                    if (BinaryCertificate == null || BinaryCertificate.Length == 0)
                    {
                        throw new ArgumentException("Binary certificate is required", nameof(BinaryCertificate));
                    }
                    if (!string.IsNullOrWhiteSpace(FilePath) && !string.IsNullOrWhiteSpace(Thumbprint))
                        throw new ArgumentException("Cannot specify multiple sources", nameof(BinaryCertificate));
                    break;
                case CertificateSource.None:
                default:
                    throw new ArgumentOutOfRangeException($"Unexpected certificate source {nameof(Source)}");
            }
        }

        /// <summary>
        /// Creates a certificate config from file path
        /// </summary>
        public static CertificateConfig FromFile(string filePath, string password = null) =>
            new CertificateConfig { Source = CertificateSource.File, FilePath = filePath, Password = password ?? string.Empty };

        /// <summary>
        /// Creates a certificate config from certificate store
        /// </summary>
        public static CertificateConfig FromStore(string thumbprint, StoreLocation storeLocation = StoreLocation.CurrentUser, StoreName storeName = StoreName.My) =>
            new CertificateConfig { Source = CertificateSource.Store, Thumbprint = thumbprint, StoreLocation = storeLocation, StoreName = storeName };
        
        /// <summary>
        /// Creates a certificate config from binary data
        /// </summary>
        public static CertificateConfig FromBinaryData(byte[] certificate) =>
            new CertificateConfig { Source = CertificateSource.Binary, BinaryCertificate = certificate };
    }
}