using EcryptAndDecrypt.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EcryptAndDecrypt.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private static IWebHostEnvironment _hostEnvironment;

        public HomeController(IWebHostEnvironment environment)
        {
            _hostEnvironment = environment;
        }

        public IActionResult Index()
        {
            var data = "Hello WorldI can ";

            string parth = Path.Combine(_hostEnvironment.WebRootPath, "aes_new", "sample.pdf");
            var steam = System.IO.File.ReadAllBytes(parth);
            var encryptdat =  EncryptUsingCertificateAsync(steam);

            string parthenc = Path.Combine(_hostEnvironment.WebRootPath, "aes_new", "Scan_encript.pdf");
            var encriptsteam = new FileStream(parthenc , FileMode.Open);

            var orginaldata =  DecryptUsingCertificate(encriptsteam);

            return View();



        }

        public IActionResult Privacy()
        {
            return View();
        }

        public static string EncryptUsingCertificateAsync(byte[] byteData)
        {
            try
            {

 
                string rsa_parth = Path.Combine(_hostEnvironment.WebRootPath, "aes_new", "certificate.pfx");
                var collection = new X509Certificate2Collection();
                collection.Import(rsa_parth, "admin123$");
                var certificate = collection[0];
                var output = "";
                using (RSA csp = (RSA)certificate.PublicKey.Key)
                {

                  
                    var aes = Aes.Create();
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    aes.GenerateKey();
                    aes.GenerateIV();
                    string parth = Path.Combine(_hostEnvironment.WebRootPath, "aes_new", "sample.pdf");
                    string parthCreate = Path.Combine(_hostEnvironment.WebRootPath, "aes_new", "Scan_encript.pdf");
                    using (var dataStream = System.IO.File.OpenRead(parth))
                    using (var secretFileStream = System.IO.File.Create(parthCreate))
                    {
                         secretFileStream.Write(aes.IV);
                         secretFileStream.Write(csp.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256));

                        using (var cryptoStream = new CryptoStream(secretFileStream, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write))
                        {
                             dataStream.CopyTo(cryptoStream);
                        }
                    }
                }
                

                


                /////////////////////////////////////////////////////////////////////////////////

                ////byte[] byteData = Encoding.UTF8.GetBytes(data);
                //string path = Path.Combine(_hostEnvironment.WebRootPath,"aes", "public-key.pem");
                //var collection = new X509Certificate2Collection();
                //collection.Import(path,"admin123$");
                //var certificate = collection[0];
                //var output = "";
                //using (RSA csp = (RSA)certificate.PublicKey.Key)
                //{
                //    byte[] bytesEncrypted = csp.Encrypt(byteData, RSAEncryptionPadding.OaepSHA1);
                //    output = Convert.ToBase64String(bytesEncrypted);
                //}
                return output;
             
            }
            catch (Exception ex)
            {
                return "";
            }
        }
        public static string DecryptUsingCertificate(Stream encryptedBlob)
        {
            try
            {


                string pathNew = Path.Combine(_hostEnvironment.WebRootPath,"aes_new", "certificate.pfx");
                var Password = "admin123$";//Note This Password is That Password That We Have Put On Generate Keys  
                var collection = new X509Certificate2Collection();
                collection.Import(System.IO.File.ReadAllBytes(pathNew), Password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                X509Certificate2 certificate = new X509Certificate2();
                certificate = collection[0];
                foreach (var cert in collection)
                {
                    //if (cert.FriendlyName.Contains("my certificate"))
                    //{
                    certificate = cert;
                    //}
                }
                if (certificate.HasPrivateKey)
                {
                    RSA csp = (RSA)certificate.PrivateKey;

                    var aes = Aes.Create();

                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    var ivBuffer = new byte[16];
                    while (encryptedBlob.Read(ivBuffer, 0, ivBuffer.Length) != ivBuffer.Length)
                    { }

                    aes.IV = ivBuffer;

                    var keyBuffer = new byte[256];
                    while (encryptedBlob.Read(keyBuffer, 0, keyBuffer.Length) != keyBuffer.Length) ;

                    string decriptParth = Path.Combine(_hostEnvironment.WebRootPath, "aes_new", "Scan-decription.pdf");
                   

                    aes.Key = csp.Decrypt(keyBuffer, RSAEncryptionPadding.OaepSHA256);

                    using (var dataStream = System.IO.File.Create(decriptParth))
                    using (var cryptoStream = new CryptoStream(encryptedBlob, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read))
                    {
                        cryptoStream.CopyTo(dataStream);
                    }

                }


                string path = Path.Combine(_hostEnvironment.WebRootPath,"aes_new", "private-key.pem");
               
               

                //using var rsa = RSA.Create();
                //var sdsdds = System.IO.File.ReadAllText(path);
                ////rsa.ImportFromPem(sdsdds.ToCharArray());

                //rsa.ImportFromEncryptedPem(sdsdds.ToCharArray(), Password.ToCharArray());

                //var aes = Aes.Create();

                //    aes.Mode = CipherMode.CBC;
                //    aes.Padding = PaddingMode.PKCS7;

                //    var ivBuffer = new byte[16];
                //    while (encryptedBlob.Read(ivBuffer, 0, ivBuffer.Length) != ivBuffer.Length)
                //    { }

                //    aes.IV = ivBuffer;

                //    var keyBuffer = new byte[256];
                //    while (encryptedBlob.Read(keyBuffer, 0, keyBuffer.Length) != keyBuffer.Length) ;

                //    string decriptParth = Path.Combine(_hostEnvironment.WebRootPath, "aes", "Scan-decription.txt");
                //    string parth = Path.Combine(_hostEnvironment.WebRootPath, "Scan.txt");

                //    using (var secretFileStream = System.IO.File.Create(decriptParth))
                //    {
                //        secretFileStream.Write(aes.IV);
                //        secretFileStream.Write(rsa.Decrypt(keyBuffer, RSAEncryptionPadding.OaepSHA256));
                //        using (var dataStream = System.IO.File.OpenRead(parth))
                //        using (var cryptoStream = new CryptoStream(secretFileStream, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write))
                //        {
                //            dataStream.CopyTo(cryptoStream);
                //        }
                //    }
                

                   

                
                //byte[] byteData = Convert.FromBase64String(data);
                //string path = Path.Combine(_hostEnvironment.WebRootPath, "certificate.pfx");
                //var Password = "admin123$";//Note This Password is That Password That We Have Put On Generate Keys  
                //var collection = new X509Certificate2Collection();
                //collection.Import(System.IO.File.ReadAllBytes(path), Password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                //X509Certificate2 certificate = new X509Certificate2();
                //certificate = collection[0];
                //foreach (var cert in collection)
                //{
                //    //if (cert.FriendlyName.Contains("my certificate"))
                //    //{
                //        certificate = cert;
                //    //}
                //}
                //if (certificate.HasPrivateKey)
                //{
                //    RSA csp = (RSA)certificate.PrivateKey;
                //    var privateKey = certificate.PrivateKey as RSACryptoServiceProvider;
                //    var keys = Encoding.UTF8.GetString(csp.Decrypt(byteData,RSAEncryptionPadding.OaepSHA1));
                //    return keys;
                //}
            }
            catch (Exception ex)
            {

            }
            return null;
        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
