using System;
using System.Numerics;

namespace RSAImplementation
{
    public class RSADecrypt
    {
        public byte[] DecryptBytes(byte[] bytes, Key private_key)
        {
            BigInteger plain_bigint = BigInteger.ModPow(new BigInteger(bytes), private_key.d, private_key.n);
            byte[] plain_bytes = plain_bigint.ToByteArray();

            return plain_bytes;
        }
    }
}