# MBSD.CyberArk.CCPClient

A clean, simple, and robust .NET Standard library for integrating with CyberArk Central Credential Provider (CCP) with **maximum flexibility** for enterprise scenarios.

## ⚠️ Important Disclaimers

**This library is developed independently by Matthew Bohan and is not affiliated with, endorsed by, or sponsored by CyberArk / CyberArk Software Ltd.**

**CyberArk®, Central Credential Provider™, and related names are the property of CyberArk Software Ltd. or its affiliates.**

**This software uses only publicly available documentation and does not contain proprietary CyberArk code.**

---


## This project is a work in progress  
This is an initial version of the library, and it may not be fully functional or tested. I don't have access to a CyberArk instance from my personal computer, so contributions, feedback, and testing are welcome to help improve it.



## Features

- ✅ **Simple API** - Clean and intuitive interface with fluent configuration
- ✅ **Multiple Authentication Methods** - Application ID only, client certificates (file or certificate store)
- ✅ **Async & Sync Support** - Both asynchronous and synchronous method variants
- ✅ **Logging** - Structured logging with Microsoft.Extensions.Logging
- ✅ **SSL Configuration** - Control SSL verification and client certificates
- ✅ **Error Handling** - Comprehensive exception handling with detailed error information
- ✅ **.NET Standard 2.0** - Compatible with .NET Framework 4.6.1+, .NET Core 2.0+, and .NET 5+

## Installation

```bash
dotnet add package MBSD.CyberArk.CCPClient
```

## Quick Start

### Synchronous  Quick Start

    using System;
    using System.Diagnostics;
    using System.Net.Http;
     
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.Extensions.Options;
    
    using MBSD.CyberArk.CCPClient;
    using MBSD.CyberArk.CCPClient.Configuration;
    using MBSD.CyberArk.CCPClient.Models;
    
    
    
    namespace ConsoleApp1
    {
        internal class Program
        {
            private static void Main(string[] args)
            {
    
                var options = new CCPOptions
               
                {
                    BaseUrl = "https://ccp.company.com"
                     
                };
    
                try
                {
                  using  var httpClient = new HttpClient();
                  using  var CCPClient = new CCPClient(httpClient, Options.Create(options));
    
                    if (CCPClient.TestConnection())    // Test the connection to the CyberArk CCP server
                    {
                        Debug.WriteLine("Connection Successful!");
    
                    }
                    else
                    {
                        Debug.WriteLine("Connection Failed!");
                    }
    
    
                    // Example of getting a secret using an object ID/Account Name, Safe Name, Application ID and an optional certificate file.
                    // which is the recommended way to efficiency retrieve secrets from CyberArk CCP. 
    
                    var secret = CCPClient.GetSecret(
                        SecretRequest.ForObject("ObjectID/AccountName")
                            .InSafe("MySafeName")
                            .UsingApplicationId("MyApplicationID")
                            .UsingCertificateFile("path/to/certificate.pfx", "certificatePassword")
                    );
    
                 
                    // Example of getting a secret using an object ID/Account Name, Safe Name, Application ID and a certificate stored in the Local Machine store. 
                    var secret2 = CCPClient.GetSecret(
                        SecretRequest.ForObject("ObjectID/AccountName")
                            .InSafe("MySafeName")
                            .UsingApplicationId("MyApplicationID")
                            .UsingCertificateStore("CERT_THUMBPRINT", StoreLocation.LocalMachine, StoreName.My)
                    );
    
                    // Example of getting just the credential/password using an object ID/Account Name, Safe Name, Application ID, and specifying a folder within the safe. 
                    var password3 = CCPClient.GetPasswordOnly(
                       SecretRequest.ForObject("ObjectID/AccountName")
                           .InSafe("MySafeName")
                           .InFolder("Root")
                           .UsingApplicationId("MyApplicationID")
                          );

    
                }
                catch (CCPException ccpEx)
                {
                    Debug.WriteLine($"Error: ApplicationID: {ccpEx.ApplicationId}");
                    Debug.WriteLine($"Error Code: {ccpEx.ErrorCode}");
                    Debug.WriteLine($"HTTP Status Code: {ccpEx.HttpStatusCode}");
                    Debug.WriteLine($"Response: {ccpEx.ResponseContent}");
    
                }
                
    
            }
        }
    }


### Asyncronous Usage

// Retrieve a secret using an object ID/Account Name, Safe Name, and an application ID using Async. 
var secret = await CCPClient.GetSecretAsync(
    SecretRequest.ForObject("ObjectID/AccountName")
        .InSafe("MySafeName")
        .UsingApplicationId("MyApplicationID")
        
);


### Supplying the handler for certificate authentication

For certificate authentication the client builds its own `HttpClientHandler`. To control how those requests connect
(for example, to restrict which addresses they may reach or to disable redirects), pass a handler factory. It receives
the loaded client certificate; the handler it returns must attach that certificate and verify the server certificate
itself, since `VerifySsl` does not apply to it. The client still sets the base address, timeout and User-Agent, and
disposes the handler and certificate when it is disposed.

    using var ccpClient = new CCPClient(httpClient, Options.Create(options), logger,
        certificate =>
        {
            var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false };
            handler.SslOptions.ClientCertificates = new X509CertificateCollection { certificate };
            return handler;
        });

### Response size

`CCPOptions.MaxResponseContentBytes` (default 1 MiB) caps the response body the client reads; a larger response fails
the request with a `CCPException`. `TimeoutSeconds` covers the whole request, including reading the body.


 

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Legal Information

This library is developed independently by Matthew Bohan and is not affiliated with, endorsed by, or sponsored by CyberArk / CyberArk Software Ltd.

CyberArk®, Central Credential Provider™, and related names are the property of CyberArk Software Ltd. or its affiliates.

This software uses only publicly available documentation and does not contain proprietary CyberArk code.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

Please ensure all contributions comply with the Apache License 2.0 and do not include any proprietary CyberArk code or documentation.

## Support

For issues and questions:
- GitHub Issues: [Report bugs and request features](https://github.com/matthewbohan/mbsd-cyberark-CCPclient/issues)
- CyberArk Documentation: [Official CCP documentation](https://docs.cyberark.com/)
- Note: CyberArk will be unable to provide support for this unofficial library - please contact me directly instead. 

   
