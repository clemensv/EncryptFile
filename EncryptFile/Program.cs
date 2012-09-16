using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptFile
{
    class Program
    {
        static int Main(string[] args)
        {
            string inputFilename = null;
            string outputFilename = null;
            string password = null;
            bool decrypt = false;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].StartsWith("-"))
                {
                    switch (args[i].Substring(1).ToLower())
                    {
                        case "i":
                            if (i + 1 >= args.Length)
                                return 1;
                            inputFilename = args[++i];
                            break;
                        case "o":
                            if (i + 1 >= args.Length)
                                return 1;
                            outputFilename = args[++i];
                            break;
                        case "r":
                            outputFilename = Guid.NewGuid().ToString("N");
                            break;
                        case "p":
                            if (i + 1 >= args.Length)
                                return 1;
                            password = args[++i];
                            break;
                        case "d":
                            decrypt = true;
                            break;
                    }
                }
                else
                {
                    Console.WriteLine("unknown option or command {0}", args[i]);
                    return 1;
                }
            }

            try
            {
                if (decrypt)
                {
                    DecryptFile(inputFilename, outputFilename, password).Wait();
                }
                else
                {
                    EncryptFile(inputFilename, outputFilename, password).Wait();
                }
            }
            catch (AggregateException agg)
            {
                foreach (var item in agg.InnerExceptions)
                {
                    Console.WriteLine(item.Message);
                }
                return 2;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return 2; 
            }
            return 0;

        }

        private async static Task EncryptFile(string inputFilename, string outputFilename, string password)
        {
            var buffer = new byte[1024 * 1024 * 1];
            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));

            using (FileStream input = new FileStream(inputFilename, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                using (FileStream outputRaw = new FileStream(outputFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    var aes = Aes.Create();
                    var iv = aes.IV;

                    var encryptor = aes.CreateEncryptor(hash, iv);

                    BinaryWriter bw = new BinaryWriter(outputRaw);
                    bw.Write(iv.Length);
                    bw.Write(iv);
                    bw.Flush();

                    int bytesRead;

                    using (var output = new CryptoStream(outputRaw, encryptor, CryptoStreamMode.Write))
                    {
                        do
                        {
                            bytesRead = await input.ReadAsync(buffer, 0, buffer.Length);
                            if (bytesRead > 0)
                            {
                                await output.WriteAsync(buffer, 0, bytesRead);
                            }
                        }
                        while (bytesRead > 0);
                    }
                }
            }
        }

        private async static Task DecryptFile(string inputFilename, string outputFilename, string password)
        {
            var buffer = new byte[1024*1024*1];
            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));

            using (FileStream inputRaw = new FileStream(inputFilename, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                BinaryReader br = new BinaryReader(inputRaw);
                var ivl = br.ReadInt32();
                var iv = br.ReadBytes(ivl);

                using (FileStream output = new FileStream(outputFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    var aes = Aes.Create();
                    var decryptor = aes.CreateDecryptor(hash, iv);
                    using (var input = new CryptoStream(inputRaw, decryptor, CryptoStreamMode.Read))
                    {
                        int bytesRead;

                        do
                        {
                            bytesRead = await input.ReadAsync(buffer, 0, buffer.Length);
                            if (bytesRead > 0)
                            {
                                await output.WriteAsync(buffer, 0, bytesRead);
                            }
                        }
                        while (bytesRead > 0);
                    }
                }
            }
        }
    }
}
