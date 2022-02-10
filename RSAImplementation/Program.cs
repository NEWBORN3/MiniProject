using System;
using System.Numerics;
using System.Text;

namespace RSAImplementation
{
    class program
    {
        static void Main(string[] args)
        {
            KeyGenerate keyPair = new KeyGenerate();
            string tryThis = "Hello now try this";
            var result = keyPair.GenerateKey();
            RSAEncrypt encr = new RSAEncrypt();
            RSADecrypt deEcr = new RSADecrypt();
            var theEncrypted = encr.EncryptBytes(Encoding.ASCII.GetBytes(tryThis), result.publicKey);
          
            Console.WriteLine(Encoding.ASCII.GetString(theEncrypted));    

            var theDecrypted = deEcr.DecryptBytes(theEncrypted, result.privateKey);
            // Console.WriteLine(Encoding.ASCII.GetString(theDecrypted));


        }
    }
}