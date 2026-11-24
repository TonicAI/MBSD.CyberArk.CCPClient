using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MBSD.CyberArk.CCPClient.Configuration;
using MBSD.CyberArk.CCPClient.Models;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace MBSD.CyberArk.CCPClient.Tests
{
    [TestClass]
    public sealed class CCPClientTests
    {
        private const string BaseUrl = "https://ccp.example.test/";
        private const string Password = "p@ss";
        private const string SecretJson = "{\"Content\":\"s3cret\",\"UserName\":\"svc\"}";

        private static X509Certificate2 _certificate;
        private static byte[] _pfx;

        [ClassInitialize]
        public static void ClassInitialize(TestContext context)
        {
            using (var rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest("CN=ccp-client-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                _certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            }

            _pfx = _certificate.Export(X509ContentType.Pkcs12, Password);
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
            _certificate?.Dispose();
        }

        [TestMethod]
        public async Task GetSecretAsync_WithCertificateAndHandlerFactory_SendsThroughFactoryHandlerWithLoadedCertificate()
        {
            var handler = new StubHandler(_ => Json(SecretJson));
            X509Certificate2 received = null;
            using (var client = CreateClient(new StubHandler(_ => throw new AssertFailedException("default client used")), certificate =>
                   {
                       received = certificate;
                       return handler;
                   }))
            {
                var secret = await client.GetSecretAsync(CertificateRequest(_pfx, Password));

                Assert.AreEqual("s3cret", secret.Content);
                Assert.IsNotNull(received);
                Assert.IsTrue(received.HasPrivateKey);
                Assert.AreEqual(_certificate.Thumbprint, received.Thumbprint);

                var sent = handler.Requests.Single();
                Assert.AreEqual("ccp.example.test", sent.RequestUri.Host);
                StringAssert.StartsWith(sent.Headers.UserAgent.ToString(), "MBSD-CyberArk-CCPClient/1.1.0");
            }
        }

        [TestMethod]
        public async Task GetSecretAsync_SameCertificateTwice_BuildsOneHandler()
        {
            var factoryCalls = 0;
            using (var client = CreateClient(new StubHandler(_ => Json(SecretJson)), _ =>
                   {
                       factoryCalls++;
                       return new StubHandler(__ => Json(SecretJson));
                   }))
            {
                await client.GetSecretAsync(CertificateRequest(_pfx, Password));
                await client.GetSecretAsync(CertificateRequest(_pfx.ToArray(), Password));

                Assert.AreEqual(1, factoryCalls);
            }
        }

        [TestMethod]
        public async Task GetSecretAsync_WithoutCertificate_UsesInjectedClientNotFactory()
        {
            var defaultHandler = new StubHandler(_ => Json(SecretJson));
            using (var client = CreateClient(defaultHandler, _ => throw new AssertFailedException("factory used")))
            {
                var secret = await client.GetSecretAsync(SecretRequest.ForObjectInSafe("app", "safe", "object"));

                Assert.AreEqual("s3cret", secret.Content);
                Assert.AreEqual(1, defaultHandler.Requests.Count);
            }
        }

        [TestMethod]
        public async Task GetSecretAsync_CertificateOnlyCopyOfCachedCertificate_IsRefusedNotReused()
        {
            var factoryCalls = 0;
            using (var publicOnly = X509CertificateLoader.LoadCertificate(_certificate.RawData))
            using (var client = CreateClient(new StubHandler(_ => Json(SecretJson)), _ =>
                   {
                       factoryCalls++;
                       return new StubHandler(__ => Json(SecretJson));
                   }))
            {
                await client.GetSecretAsync(CertificateRequest(_pfx, Password));

                var publicOnlyPfx = publicOnly.Export(X509ContentType.Pkcs12);
                var ex = await Assert.ThrowsExceptionAsync<CCPException>(() => client.GetSecretAsync(CertificateRequest(publicOnlyPfx, null)));

                StringAssert.Contains(ex.Message, "no private key");
                Assert.AreEqual(1, factoryCalls);
            }
        }

        [TestMethod]
        public async Task GetSecretAsync_CachedCertificateWithWrongPassword_IsRefusedNotReused()
        {
            using (var client = CreateClient(new StubHandler(_ => Json(SecretJson)), _ => new StubHandler(__ => Json(SecretJson))))
            {
                await client.GetSecretAsync(CertificateRequest(_pfx, Password));

                await Assert.ThrowsExceptionAsync<CCPException>(() => client.GetSecretAsync(CertificateRequest(_pfx, "wrong")));
            }
        }

        [TestMethod]
        public async Task GetSecretAsync_ReservedCharactersInValues_AreEscaped()
        {
            var handler = new StubHandler(_ => Json(SecretJson));
            using (var client = CreateClient(handler))
            {
                var request = SecretRequest.ForObjectInSafe("app id", "safe#1&Folder=Root", "my object+50%");
                request.CustomParameters["Reason=x&y"] = "a b";

                await client.GetSecretAsync(request);

                var query = handler.Requests.Single().RequestUri.Query;
                StringAssert.Contains(query, "AppID=app%20id");
                StringAssert.Contains(query, "Safe=safe%231%26Folder%3DRoot");
                StringAssert.Contains(query, "Object=my%20object%2B50%25");
                StringAssert.Contains(query, "Reason%3Dx%26y=a%20b");
                Assert.IsFalse(query.Contains("&Folder="), query);
            }
        }

        [TestMethod]
        public async Task GetSecretAsync_ResponseWithContentLengthOverLimit_Fails()
        {
            using (var client = CreateClient(new StubHandler(_ => Json(new string('x', 2048))), maxResponseContentBytes: 1024))
            {
                var ex = await Assert.ThrowsExceptionAsync<CCPException>(
                    () => client.GetSecretAsync(SecretRequest.ForObjectInSafe("app", "safe", "object")));

                StringAssert.Contains(ex.Message, "1024-byte limit");
            }
        }

        [TestMethod]
        public async Task GetSecretAsync_StreamedResponseOverLimit_Fails()
        {
            var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                // No Content-Length, so the limit has to be enforced while reading.
                Content = new StreamContent(new UnknownLengthStream(new byte[64 * 1024])),
            });
            using (var client = CreateClient(handler, maxResponseContentBytes: 1024))
            {
                var ex = await Assert.ThrowsExceptionAsync<CCPException>(
                    () => client.GetSecretAsync(SecretRequest.ForObjectInSafe("app", "safe", "object")));

                StringAssert.Contains(ex.Message, "1024-byte limit");
            }
        }

        [TestMethod]
        public async Task GetSecretAsync_ErrorStatus_KeepsResponseContentOnException()
        {
            const string error = "{\"ErrorCode\":\"APPAP004E\",\"ErrorMsg\":\"Password object matching query not found\"}";
            var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent(error) });
            using (var client = CreateClient(handler))
            {
                var ex = await Assert.ThrowsExceptionAsync<CCPException>(
                    () => client.GetSecretAsync(SecretRequest.ForObjectInSafe("app", "safe", "object")));

                Assert.AreEqual(404, ex.HttpStatusCode);
                Assert.AreEqual(error, ex.ResponseContent);
            }
        }

        [TestMethod]
        public async Task GetSecretAsync_HandlerFactoryReturnsNull_Throws()
        {
            using (var client = CreateClient(new StubHandler(_ => Json(SecretJson)), _ => null))
            {
                await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => client.GetSecretAsync(CertificateRequest(_pfx, Password)));
            }
        }

        [TestMethod]
        public async Task Dispose_DisposesFactoryHandlerAndCertificate()
        {
            var handler = new StubHandler(_ => Json(SecretJson));
            X509Certificate2 received = null;
            var client = CreateClient(new StubHandler(_ => Json(SecretJson)), certificate =>
            {
                received = certificate;
                return handler;
            });
            await client.GetSecretAsync(CertificateRequest(_pfx, Password));

            client.Dispose();

            Assert.IsTrue(handler.Disposed);
            Assert.AreEqual(IntPtr.Zero, received.Handle);
        }

        private static CCPClient CreateClient(
            HttpMessageHandler defaultHandler,
            Func<X509Certificate2, HttpMessageHandler> certificateHandlerFactory = null,
            long maxResponseContentBytes = 1024 * 1024)
        {
            var options = new CCPOptions { BaseUrl = BaseUrl, DefaultApplicationId = "app", MaxResponseContentBytes = maxResponseContentBytes };
            return new CCPClient(new HttpClient(defaultHandler), Options.Create(options), certificateHandlerFactory: certificateHandlerFactory);
        }

        private static SecretRequest CertificateRequest(byte[] pfx, string password) =>
            SecretRequest.ForObjectInSafe("app", "safe", "object").UsingCertificate(CertificateConfig.FromBinaryData(pfx, password));

        private static HttpResponseMessage Json(string body) =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

        private sealed class StubHandler : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;

            public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
            {
                _respond = respond;
            }

            public List<HttpRequestMessage> Requests { get; } = new List<HttpRequestMessage>();

            public bool Disposed { get; private set; }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Requests.Add(request);
                return Task.FromResult(_respond(request));
            }

            protected override void Dispose(bool disposing)
            {
                Disposed = true;
                base.Dispose(disposing);
            }
        }

        /// <summary>
        /// A readable stream that does not report its length, so <see cref="StreamContent"/> sends no Content-Length.
        /// </summary>
        private sealed class UnknownLengthStream : MemoryStream
        {
            public UnknownLengthStream(byte[] buffer) : base(buffer)
            {
            }

            public override bool CanSeek => false;
        }
    }
}
