using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace EcryptAndDecrypt.Controllers
{
    public class EncriptionController : Controller
    {
        private readonly ILogger<EncriptionController> _logger;
        private static IWebHostEnvironment _hostEnvironment;

        public EncriptionController(IWebHostEnvironment environment)
        {
            _hostEnvironment = environment;
        }

        public IActionResult Index()
        {
            string parth = Path.Combine(_hostEnvironment.WebRootPath, "Scan.txt");
            var steam = System.IO.File.ReadAllText(parth);
            var encryptdat = EncryptUsingCertificate(steam);

           // var orginaldata = DecryptUsingCertificate(encryptdat);

            return View();
        }


        public static string EncryptUsingCertificate(string byteData)
        {
            try
            {


                //byte[] byteData = Encoding.UTF8.GetBytes(data);
                string path = Path.Combine(_hostEnvironment.WebRootPath,"aes", "public-key.pem");
                var collection = new X509Certificate2Collection();
                collection.Import(path, "admin123$");
                var certificate = collection[0];
                var output = "";
                using (RSA csp = (RSA)certificate.PublicKey.Key)
                {

                    /////////////////////////////////////////////////////////////////
                    var dataStream = System.IO.File.ReadAllBytes("C:\\Encrypt\\aes\\sample.txt");

                    var key = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                    var iv = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

                    var encrypted = Encrypt(dataStream, csp.ExportRSAPublicKey(), iv);
                    var str = BitConverter.ToString(encrypted).Replace("-", "");
                    Console.WriteLine(str);

                    var decrypted = Decrypt(encrypted, key, iv);

                    string datetimeticks = DateTime.Now.Ticks.ToString();

                    System.IO.File.WriteAllBytes("C:\\Encrypt\\aes\\Decrypted-File-" + datetimeticks + ".txt", decrypted);

                    /////////////////////////////////////////////////////////////////


                    //using (Rijndael myRijndael = Rijndael.Create())
                    //{
                    //    myRijndael.KeySize = 2048;
                    //    myRijndael.Key = csp.ExportRSAPublicKey();
                    //    // Encrypt the string to an array of bytes.
                    //    byte[] encrypted = EncryptStringToBytes(byteData, myRijndael.Key, myRijndael.IV);

                    //    using (var secretFileStream = System.IO.File.Create("D:\\Project\\File\\Encripted\\Scan.txt"))
                    //    {
                    //        secretFileStream.Write(encrypted);

                    //    }

                    //    var sdsd = encrypted;
                    //    // Decrypt the bytes to a string.
                    //    //string roundtrip = DecryptStringFromBytes(encrypted, myRijndael.Key, myRijndael.IV);

                    //    //Display the original data and the decrypted data.
                    //    //Console.WriteLine("Original Text from file: {0}", original);
                    //    //Console.WriteLine("After Encryption and Decryption: {0}", roundtrip);
                    //}

                    //byte[] bytesEncrypted = csp.Encrypt(byteData, RSAEncryptionPadding.OaepSHA1);
                    //output = Convert.ToBase64String(bytesEncrypted);
                }
                return output;

            }
            catch (Exception ex)
            {
                return "";
            }
        }

        public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.Zeros;

                aes.Key = key;
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(data, encryptor);
                }
            }
        }

        public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.Zeros;

                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(data, decryptor);
                }
            }
        }


        private static byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();
                return ms.ToArray();
            }
        }

        private static byte[] EncryptStringToBytes(string original, byte[] key, byte[] IV)
        {
            byte[] encrypted;
            // Create an Rijndael object with the specified key and IV.
            using (Rijndael rijAlg = Rijndael.Create())
            {
                rijAlg.Key = key;
                rijAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(original);
                            
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
    }
}
