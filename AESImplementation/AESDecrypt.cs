using System;
using System.Collections.Generic;

namespace AESImplementation
{
    public class AESDecrypt
    {
        public byte[] DecryptByte(byte[] ciphertext, byte[] key)
        {
            byte[,] expandKey = AESUtility.ExpandKey(key);

            byte[] counterBlock = new byte[16];
            ciphertext.Slice(0, 8).CopyTo(counterBlock,0);

            int nBlocks = Convert.ToInt32(Math.Ceiling((double)(ciphertext.Length - 8) / 16));
            byte[][] ct = new byte[nBlocks][];
            for (var b = 0; b < nBlocks; b++)
            {
                int start = 8 + b * 16;
                int end = start + 16;
                if (end > ciphertext.Length)
                    end = ciphertext.Length;
                ct[b] = ciphertext.Slice(start, end);
            }

            byte[][] plaintxtarr = new byte[nBlocks][];
            List<byte> plaintext = new List<byte>();

            for (int b = 0; b < nBlocks; b++)
            {
                for (int c = 0; c < 4; c++)
                {
                    counterBlock[15 - c] = (byte)((byte)( ((UInt32)b) >> c * 8) & 0xff);
                }
                for (int c = 0; c < 4; c++)
                {
                    counterBlock[15 - c - 4] = (byte)((byte)( ((UInt32)(((b + 1) / (double)0x100000000) - 1)) >> c * 8) & 0xff);
                }

                byte[] cipherCntr = AESUtility.CipherByte(counterBlock, expandKey);  

                byte[] plaintxtByte = new byte[ct[b].Length];

                for (int i = 0; i < ct[b].Length; i++)
                {
                    plaintxtByte[i] = (byte)(cipherCntr[i] ^ ct[b][i]);
                }
                plaintxtarr[b] = plaintxtByte;
                plaintext.AddRange(plaintxtByte);
            }
            return plaintext.ToArray();
        }
    }
}