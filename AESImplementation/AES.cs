using System.Text;

namespace AESImplementation
{

    public class Aes128Ctr
    {
        #region Const
        private const int _Nb = 4; // block size (in words): no of columns in state (fixed at 4 for AES)
        private const int _Ws = 4; // Word size is 4 bytes
        private const int _BlockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
        private static int _CountRound = 11;

        private static byte[] _sbox = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };

        private static byte[,] _rCon = { {0x00, 0x00, 0x00, 0x00},
             {0x01, 0x00, 0x00, 0x00},
             {0x02, 0x00, 0x00, 0x00},
             {0x04, 0x00, 0x00, 0x00},
             {0x08, 0x00, 0x00, 0x00},
             {0x10, 0x00, 0x00, 0x00},
             {0x20, 0x00, 0x00, 0x00},
             {0x40, 0x00, 0x00, 0x00},
             {0x80, 0x00, 0x00, 0x00},
             {0x1b, 0x00, 0x00, 0x00},
             {0x36, 0x00, 0x00, 0x00} };


        private byte[] _Key;
        #endregion

        #region c'tors

        public Aes128Ctr(byte[] key)
        {
            this._Key = key;
        }

        public Aes128Ctr(string sKey, int nBits)
        {
            _Key = BuildKey(sKey, nBits);
        }

        /// <summary>
        /// Extends a key to 16/24/32 bytes
        /// </summary>
        /// <param name="sKey"></param>
        /// <param name="nBits"></param>
        /// <returns></returns>
        private static byte[] BuildKey(string sKey, int nBits)
        {
            if (!(nBits == 128 || nBits == 192 || nBits == 256))
                throw new Exception("standard allows 128/192/256 bit keys");
            byte[] keyBytes = ASCIIEncoding.UTF8.GetBytes(sKey);
            var nBytes = nBits / 8; // no bytes in key (16/24/32)
            byte[] key = new byte[nBytes];
            for (int i = 0; i < nBytes; i++)
            {
                if (i >= keyBytes.Length)
                    key[i] = 0;
                else
                    key[i] = keyBytes[i];
            }
            return key;
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// AES Cipher function: encrypt 'input' state with Rijndael algorithm
        /// applies Nr rounds (10/12/14) using key schedule w for 'add round key' stage
        /// </summary>
        /// <param name="input">input 16-byte (128-bit) input state array</param>
        /// <param name="w">Key schedule as 2D byte-array (Nr+1 x Nb bytes)</param>
        /// <returns>Encrypted output state array</returns>
        private byte[] Cipher(byte[] input, byte[,] w)
        {
            int Nk = _Key.Length / _Ws; // key length (in words): 4/6/8 for 128/192/256-bit keys
            int Nr = Nk + 6;          // no of rounds: 10/12/14 for 128/192/256-bit keys

            byte[,] state = new byte[_Ws, _Nb];  // initialise 4xNb byte-array 'state' with input [§3.4]
            for (var i = 0; i < (_Ws * _Nb); i++)
            {
                state[i % _Ws, Convert.ToInt32(Math.Floor((double)(i / _Ws)))] = input[i];
            }

            state = AddRoundKey(state, w, 0);

            for (var round = 1; round < Nr; round++)
            {
                state = SubBytes(state);
                state = ShiftRows(state);
                state = MixColumns(state);
                state = AddRoundKey(state, w, round);
            }

            state = SubBytes(state);
            state = ShiftRows(state);
            state = AddRoundKey(state, w, Nr);

            var output = new byte[_Ws * _Nb];  // convert state to 1-d array before returning [§3.4]
            for (var i = 0; i < _Ws * _Nb; i++)
            {
                output[i] = state[i % _Ws, Convert.ToInt32(Math.Floor((double)(i / _Ws)))];
            }
            return output;
        }

        /// <summary>
        /// Perform Key Expansion to generate a Key Schedule
        /// </summary>
        /// <returns>Expanded key schedule as 2D byte-array (Nr+1 x Nb bytes)</returns>
        private byte[,] KeyExpansion(byte[] key)
        {
            int Nk = key.Length / _Ws;  // key length (in words): 4/6/8 for 128/192/256-bit keys
            int Nr = Nk + 6;       // no of rounds: 10/12/14 for 128/192/256-bit keys

            byte[,] w = new byte[(_Nb * (Nr + 1)), _Nb];
            byte[] temp = new byte[_Ws];

            for (int i = 0; i < Nk; i++)
            {
                w[i, 0] = key[_Ws * i];
                w[i, 1] = key[_Ws * i + 1];
                w[i, 2] = key[_Ws * i + 2];
                w[i, 3] = key[_Ws * i + 3];
            }

            for (int i = Nk; i < (_Nb * (Nr + 1)); i++)
            {
                w[i, 0] = 0;
                w[i, 1] = 0;
                w[i, 2] = 0;
                w[i, 3] = 0;
                for (var t = 0; t < _Ws; t++)
                    temp[t] = w[i - 1, t];
                if (i % Nk == 0)
                {
                    temp = SubWord(RotWord(temp));
                    for (var t = 0; t < _Ws; t++)
                        temp[t] ^= _rCon[(i / Nk), t];
                }
                else if (Nk > 6 && i % Nk == _Ws)
                {
                    temp = SubWord(temp);
                }
                for (var t = 0; t < _Ws; t++)
                {
                    w[i, t] = (byte)(w[(i - Nk), t] ^ temp[t]);
                }
            }
            return w;
        }

        /// <summary>
        /// Perform Key Expansion on my key
        /// </summary>
        /// <returns></returns>
        private byte[,] KeyExpansion()
        {
            return KeyExpansion(_Key);
        }


        /// <summary>
        /// xor Round Key into state S [§5.1.4]
        /// </summary>
        /// <param name="state"></param>
        /// <param name="w"></param>
        /// <param name="rnd"></param>
        /// <returns></returns>
        private static byte[,] AddRoundKey(byte[,] state, byte[,] w, int rnd)
        {
            for (var r = 0; r < _Ws; r++)
            {
                for (var c = 0; c < _Nb; c++)
                {
                    state[r,c] ^= w[rnd * _Ws + c, r];
                }
            }
            return state;
        }

        /// <summary>
        /// apply SBox to 4-byte word w
        /// </summary>
        /// <param name="w"></param>
        /// <returns></returns>
        private byte[] SubWord(byte[] w)
        {
            // apply SBox to 4-byte word w
            for (var i = 0; i < _Ws; i++)
                w[i] = _sbox[w[i]];
            return w;
        }

        /// <summary>
        /// rotate 4-byte word w left by one byte
        /// </summary>
        /// <param name="w"></param>
        /// <returns></returns>
        private byte[] RotWord(byte[] w)
        {
            // rotate 4-byte word w left by one byte
            var tmp = w[0];
            for (var i = 0; i < (_Ws - 1); i++)
                w[i] = w[i + 1];
            w[(_Ws - 1)] = tmp;
            return w;
        }

        /// <summary>
        /// apply SBox to state S [§5.1.1]
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        private byte[,] SubBytes(byte[,] s)
        {
            for (var r = 0; r < 4; r++)
            {
                for (var c = 0; c < _Nb; c++)
                {
                    s[r,c] = _sbox[s[r,c]];
                }
            }
            return s;
        }

        /// <summary>
        /// shift row r of state S left by r bytes [§5.1.2]
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        private byte[,] ShiftRows(byte[,] s)
        {
            byte[] t = new byte[_Ws];
            for (int r = 1; r < _Ws; r++)
            {
                for (int c = 0; c < _Ws; c++)
                {
                    t[c] = s[r, (c + r) % _Nb];  // shift into temp copy
                }
                for (int c = 0; c < _Ws; c++)
                {
                    s[r, c] = t[c];         // and copy back
                }
            }          
            // note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
            return s;  // see asmaes.sourceforge.net/rijndael/rijndaelImplementation.pdf
        }

        /// <summary>
        /// combine bytes of each col of state S [§5.1.3]
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        private byte[,] MixColumns(byte[,] s)
        {   
            for (var c = 0; c < _Ws; c++)
            {
                var a = new byte[_Ws];  // 'a' is a copy of the current column from 's'
                var b = new byte[_Ws];  // 'b' is a•{02} in GF(2^8)
                for (var i = 0; i < _Ws; i++)
                {
                    a[i] = s[i,c];
                    b[i] = (byte)(s[i,c] & 0x80) != 0 ? (byte)((s[i,c] << 1) ^ 0x011b) : (byte)(s[i,c] << 1);

                }
                // a[n] ^ b[n] is a•{03} in GF(2^8)
                s[0,c] = (byte) (b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]); // 2*a0 + 3*a1 + a2 + a3
                s[1,c] = (byte) (a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]); // a0 * 2*a1 + 3*a2 + a3
                s[2,c] = (byte) (a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]); // a0 + a1 + 2*a2 + 3*a3
                s[3,c] = (byte) (a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]); // 3*a0 + a1 + a2 + 2*a3
            }
            return s;
        }

        #endregion

        #region Public Methods
        
        /// <summary>
        /// Encrypt a text using AES encryption in Counter mode of operation
        /// Unicode multi-byte character safe
        /// </summary>
        /// <param name="plaintext">Source text to be encrypted</param>
        /// <returns></returns>
        public string Encrypt(string plaintext)
        {
            byte[] ciphertext = Encrypt(ASCIIEncoding.UTF8.GetBytes(plaintext));
            return Convert.ToBase64String(ciphertext);
        }

        /// <summary>
        /// Encrypt a text using AES encryption in Counter mode of operation
        /// Unicode multi-byte character safe
        /// </summary>
        /// <param name="plaintext">Source text to be encrypted</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] plaintext)
        {
            byte[,] eKey = KeyExpansion();

            // use AES to encrypt password (mirroring encrypt routine)
            byte[] key = Cipher(_Key, eKey);

            // expand key to 16/24/32 bytes long
            key = key.Concat(key.Slice(0, _Key.Length - _BlockSize)).ToArray();

            // initialise 1st 8 bytes of counter block with nonce (NIST SP800-38A §B.2): [0-1] = millisec, 
            // [2-3] = random, [4-7] = seconds, together giving full sub-millisec uniqueness up to Feb 2106
            byte[] counterBlock = new byte[_BlockSize];

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

            // and convert it to a string to go on the front of the ciphertext
            List<byte> ciphertext = new List<byte>();
            for (var i = 0; i < 8; i++)
            {
                ciphertext.Add(counterBlock[i]);
            }

            // generate key schedule
            var keySchedule = KeyExpansion(key);

            int blockCount = Convert.ToInt32(Math.Ceiling((double)plaintext.Length / _BlockSize));
            byte[][] cipherarr = new byte[blockCount][];  // ciphertext as array of strings

            for (var b = 0; b < blockCount; b++)
            {
                // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
                // done in two stages for 32-bit ops: using two words allows us to go past 2^32 blocks (68GB)
                for (var c = 0; c < 4; c++)
                {
                    counterBlock[15 - c] = (byte)((byte)(((UInt32)b) >> c * 8) & 0xff);
                }
                for (var c = 0; c < 4; c++)
                {
                    counterBlock[15 - c - 4] = (byte)(((UInt32)(b / (double)0x100000000)) >> c * 8);
                }
          
                byte[] cipherCntr = Cipher(counterBlock, keySchedule);  // -- encrypt counter block --

                // block size is reduced on final block
                int blockLength = b < blockCount - 1 ? _BlockSize : (plaintext.Length - 1) % _BlockSize + 1;
                byte[] cipherChar = new byte[blockLength];

                // -- xor plaintext with ciphered counter char-by-char --
                for (var i = 0; i < blockLength; i++)
                {  
                    cipherChar[i] = (byte) (cipherCntr[i] ^ plaintext[b * _BlockSize + i]);
                }
                cipherarr[b] = cipherChar;
                ciphertext.AddRange(cipherChar);
            }

            return ciphertext.ToArray();
        }

        /// <summary>
        /// Decrypt a text encrypted by AES in counter mode of operation
        /// </summary>
        /// <param name="ciphertext">Source text to be decrypted</param>
        /// <returns></returns>
        public string Decrypt(string ciphertext)
        {
            byte[] plaintext = Decrypt(Convert.FromBase64String(ciphertext));
            return ASCIIEncoding.UTF8.GetString(plaintext);
        }

        /// <summary>
        /// Decrypt a text encrypted by AES in counter mode of operation
        /// </summary>
        /// <param name="ciphertext">Source text to be decrypted</param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] ciphertext)
        {
            byte[,] eKey = KeyExpansion();

            // use AES to encrypt password (mirroring encrypt routine)
            byte[] key = Cipher(_Key, eKey);

            // expand key to 16/24/32 bytes long
            key = key.Concat(key.Slice(0, _Key.Length - _BlockSize)).ToArray();

            // recover nonce from 1st 8 bytes of ciphertext
            byte[] counterBlock = new byte[_BlockSize];
            ciphertext.Slice(0, 8).CopyTo(counterBlock,0);

            // generate key schedule
            var keySchedule = KeyExpansion(key);

            // separate ciphertext into blocks (skipping past initial 8 bytes)
            int nBlocks = Convert.ToInt32(Math.Ceiling((double)(ciphertext.Length - 8) / _BlockSize));
            byte[][] ct = new byte[nBlocks][];
            for (var b = 0; b < nBlocks; b++)
            {
                int start = 8 + b * _BlockSize;
                int end = start + _BlockSize;
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

                byte[] cipherCntr = Cipher(counterBlock, keySchedule);  // encrypt counter block

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
        
        #endregion
    }
}