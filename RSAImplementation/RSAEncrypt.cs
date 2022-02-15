using System;
using System.Numerics;
using System.Text;

namespace RSAImplementation
{
    public class RSAEncrypt
    {
        public byte[] EncryptBytes(byte[] bytes, Key public_key)
        {

            BigInteger cipher_bigint = BigInteger.ModPow(new BigInteger(bytes), public_key.e, public_key.n);
            return cipher_bigint.ToByteArray();
        }
    }
}