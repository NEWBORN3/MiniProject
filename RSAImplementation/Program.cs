

namespace RSAImplementation
{
    class Program
    {
        static void Main(string[] args)
        {
            var kp = RSA.GenerateKeyPair(1024);

            byte[] raw = { 0x00, 0x01, 0x02, 0x03, 0x04 };

            byte[] encrypted = RSA.EncryptBytes(raw, kp.public_);
            
        }
    }
}