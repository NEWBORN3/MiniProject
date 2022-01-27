using System.Text;
namespace AESImplementation
{
    class Program 
    {
        private static string _keystring = "Well this must b"; 
        static void Main(string[] args)
        {

            string plainText = "encrypt this now";
            
            Aes128Ctr tryA = new Aes128Ctr(Encoding.ASCII.GetBytes(_keystring));

            var result  = tryA.Encrypt(plainText);

            var theDec = tryA.Decrypt(result);

            Console.WriteLine(result);
        }

        public static byte[] EncryptCounter(byte[] counterBlock)
        {
            byte[,] expandkey = KeyExpansion.ExpandKey(ASCIIEncoding.UTF8.GetBytes(_keystring));
            byte[,] conText= new byte[4,4];
            for (int i = 0; i < 16; i++)
            {
                conText[i % 4, i /4] = counterBlock[i];
            }

            conText = KeyExpansion.AddRoundKey(conText,expandkey,0);
            for (int round = 1; round < 10; round++)
            {
                conText = KeyExpansion.SubBytes(conText);
                conText = ShiftRows.shiftRows(conText);
                conText = MixColumns.mixColumns(conText);
                conText = KeyExpansion.AddRoundKey(conText, expandkey, round);
            }

            conText = KeyExpansion.SubBytes(conText);
            conText = ShiftRows.shiftRows(conText);
            conText = KeyExpansion.AddRoundKey(conText, expandkey, 10);
           
            byte[] result = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                
                 result[i] = conText[i % 4, i / 4];
            }
            return result;
        }

        public static byte[] EncryptPlainText(string plainText)
        {
            byte[] bytePlainText = Encoding.ASCII.GetBytes(plainText);
            byte[] counterBlock = new byte[16];
            int blockCount = bytePlainText.Length / 16; 
            int nonce = DateTime.UtcNow.Millisecond % 1000; 
            Random random = new Random(nonce);
            int nonceTwo = (int)random.NextInt64(nonce) % 1000;

            for (var i = 0; i < 4; i++)
            {
                counterBlock[i] = (byte)(nonce >> i * 2);
            }
            for (var i = 0; i < 4; i++)
            {
                counterBlock[i + 4] = (byte)(nonceTwo >> i * 2);
            }
            
            List<byte> ciphertext = new List<byte>();
            for (var i = 0; i < 8; i++)
            {
                ciphertext.Add(counterBlock[i]);
            }

            for (var b = 0; b < blockCount; b++)
            {
                for (var c = 0; c < 8; c++)
                {
                    counterBlock[15 - c] = (byte)((byte)(((UInt32)b) >> c * 8) & 0xff);
                }
                byte[] cipherCntr = EncryptCounter(counterBlock);
        

               
                
                int blockLength = b < blockCount - 1 ? 16 : (bytePlainText.Length - 1) % 17;
                byte[] cipherChar = new byte[blockLength];

                
                for (var i = 0; i < blockLength; i++)
                {  
                    cipherChar[i] = (byte) (cipherCntr[i] ^ bytePlainText[b * 16 + i]);
                }
                ciphertext.AddRange(cipherChar);
                
            }
            return ciphertext.ToArray();
        }

        public static byte[] DecryptPlainText(byte[] ciphertext)
        {
            // recover nonce from 1st 8 bytes of ciphertext
            byte[] counterBlock = new byte[16];

            // generate key schedule

            // separate ciphertext into blocks (skipping past initial 8 bytes)
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

            // plaintext will get generated block-by-block into array of block-length strings
            byte[][] plaintxtarr = new byte[nBlocks][];
            List<byte> plaintext = new List<byte>();

            for (int b = 0; b < nBlocks; b++)
            {
                // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
                for (int c = 0; c < 4; c++)
                {
                    counterBlock[15 - c] = (byte)((byte)( ((UInt32)b) >> c * 8) & 0xff);
                }
                for (int c = 0; c < 4; c++)
                {
                    counterBlock[15 - c - 4] = (byte)((byte)( ((UInt32)(((b + 1) / (double)0x100000000) - 1)) >> c * 8) & 0xff);
                }

                byte[] cipherCntr = EncryptCounter(counterBlock);  // encrypt counter block

                byte[] plaintxtByte = new byte[ct[b].Length];
                for (int i = 0; i < ct[b].Length; i++)
                {
                    // -- xor plaintxt with ciphered counter byte-by-byte --
                    plaintxtByte[i] = (byte)(cipherCntr[i] ^ ct[b][i]);
                }
                plaintxtarr[b] = plaintxtByte;
                plaintext.AddRange(plaintxtByte);
            }
            return plaintext.ToArray();
        }
}
}