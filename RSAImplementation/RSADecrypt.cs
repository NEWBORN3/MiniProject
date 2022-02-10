using System;
using System.Numerics;

namespace RSAImplementation
{
    public class RSADecrypt
    {
        public byte[] DecryptBytes(byte[] bytes, Key private_key)
        {

            //Decrypting.
            var plain_bigint = new BigInteger();
            var padded_bigint = new BigInteger(bytes);
            plain_bigint = BigInteger.ModPow(padded_bigint, private_key.d, private_key.n);

            //Removing all padding bytes, including the marker 0xFF.
            byte[] plain_bytes = plain_bigint.ToByteArray();
            int lengthToCopy=-1;
            for (int i=plain_bytes.Length-1; i>=0; i--) 
            {
                if (plain_bytes[i]==0xFF)
                {
                    lengthToCopy = i;
                    break;
                }
            }

            //Checking for a failure to find marker byte.
            if (lengthToCopy==-1)
            {
                throw new Exception("Marker byte for padding (0xFF) not found in plain bytes.\nPossible Reasons:\n1: PAYLOAD TOO LARGE\n2: KEYS INVALID\n3: ENCRYPT/DECRYPT FUNCTIONS INVALID");
            }

            //Copying into return array, returning.
            byte[] return_array = new byte[lengthToCopy];
            Array.Copy(plain_bytes, return_array, lengthToCopy);
            return return_array;
        }
    }
}