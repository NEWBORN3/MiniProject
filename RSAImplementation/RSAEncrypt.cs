using System;
using System.Numerics;
using System.Text;

namespace RSAImplementation
{
    public class RSAEncrypt
    {
        public byte[] EncryptBytes(byte[] bytes, Key public_key)
        {
            //Checking that the size of the bytes is less than n, and greater than 1.
            if (1>bytes.Length || bytes.Length>=public_key.n.ToByteArray().Length)
            {
                throw new Exception("Bytes given are longer than length of key element n (" + bytes.Length + " bytes).");
            }

            //Padding the array to unsign.
            byte[] bytes_padded = new byte[bytes.Length+2];
            Array.Copy(bytes, bytes_padded, bytes.Length);
            bytes_padded[bytes_padded.Length-1] = 0x00;
            
            //Setting high byte right before the data, to prevent data loss.
            bytes_padded[bytes_padded.Length-2] = 0xFF;

            //Computing as a BigInteger the encryption operation.
            var cipher_bigint = new BigInteger();
            var padded_bigint = new BigInteger(bytes_padded);
            cipher_bigint = BigInteger.ModPow(padded_bigint, public_key.e, public_key.n);

            //Returning the byte array of encrypted bytes.
            return cipher_bigint.ToByteArray();
        }

        public byte[] EncryptBytes(string plaintext, Key public_key)
        {
            byte[] bytes = ASCIIEncoding.UTF8.GetBytes(plaintext);
            //Checking that the size of the bytes is less than n, and greater than 1.
            if (1>bytes.Length || bytes.Length>=public_key.n.ToByteArray().Length)
            {
                throw new Exception("Bytes given are longer than length of key element n (" + bytes.Length + " bytes).");
            }

            //Padding the array to unsign.
            byte[] bytes_padded = new byte[bytes.Length+2];
            Array.Copy(bytes, bytes_padded, bytes.Length);
            bytes_padded[bytes_padded.Length-1] = 0x00;
            
            //Setting high byte right before the data, to prevent data loss.
            bytes_padded[bytes_padded.Length-2] = 0xFF;

            //Computing as a BigInteger the encryption operation.
            var cipher_bigint = new BigInteger();
            var padded_bigint = new BigInteger(bytes_padded);
            cipher_bigint = BigInteger.ModPow(padded_bigint, public_key.e, public_key.n);

            //Returning the byte array of encrypted bytes.
            return cipher_bigint.ToByteArray();
        }
    }
}