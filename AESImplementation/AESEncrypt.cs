using System;
using System.Collections.Generic;

namespace AESImplementation
{
    public class AESEncrypt
    {
        public byte[] EncryptByte(byte[] plaintext, byte[] key)
        {
            byte[,] expandKey = AESUtility.ExpandKey(key);

            byte[] counterBlock = new byte[16];
            long nonce = (DateTime.UtcNow.Ticks - 621355968000000000) / 10000;  // timestamp: milliseconds since 1-Jan-1970
            long nonceMs = nonce % 1000;
            double nonceSec = Math.Floor((double) (nonce / 1000));
            Random random = new Random();
            long nonceRnd = Convert.ToInt64(Math.Floor(random.NextDouble() * (double)0xffff));

            for (var i = 0; i < 2; i++)
            {
                counterBlock[i] = (byte)((byte)(((UInt64)nonceMs) >> i * 8) & 0xff);
            }
            for (var i = 0; i < 2; i++)
            {
                counterBlock[i + 2] = (byte)((byte)(((UInt64)nonceRnd) >> i * 8) & 0xff);
            }
            for (var i = 0; i < 4; i++)
            {
                counterBlock[i + 4] = (byte)((byte)(((UInt64)nonceSec) >> i * 8) & 0xff);
            }

            List<byte> ciphertext = new List<byte>();
            for (var i = 0; i < 8; i++)
            {
                ciphertext.Add(counterBlock[i]);
            }

            int blockCount = Convert.ToInt32(Math.Ceiling((double)plaintext.Length / 16));
            byte[][] cipherarr = new byte[blockCount][];  
            
            for (var b = 0; b < blockCount; b++)
            {
                for (var c = 0; c < 4; c++)
                {
                    counterBlock[15 - c] = (byte)((byte)(((UInt32)b) >> c * 8) & 0xff);
                }
                for (var c = 0; c < 4; c++)
                {
                    counterBlock[15 - c - 4] = (byte)(((UInt32)(b / (double)0x100000000)) >> c * 8);
                }
          
                byte[] cipherCntr = AESUtility.CipherByte(counterBlock, expandKey);  

             
                int blockLength = b < blockCount - 1 ? 16 : (plaintext.Length - 1) % 16 + 1;
                byte[] cipherChar = new byte[blockLength];

                for (var i = 0; i < blockLength; i++)
                {  
                    cipherChar[i] = (byte) (cipherCntr[i] ^ plaintext[b * 16 + i]);
                }
                cipherarr[b] = cipherChar;
                ciphertext.AddRange(cipherChar);
            }

            return ciphertext.ToArray();
        }
    }
}