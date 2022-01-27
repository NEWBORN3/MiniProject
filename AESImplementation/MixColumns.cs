namespace AESImplementation
{
    public static class MixColumns
    {
        public static byte[,] mixColumns(byte[,] s)
        {   
            for (var c = 0; c < 4; c++)
            {
                var a = new byte[4];  // 'a' is a copy of the current column from 's'
                var b = new byte[4];  // 'b' is a•{02} in GF(2^8)
                for (var i = 0; i < 4; i++)
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

        public static byte[,] ImixCoulumns(byte[,] s)
        {
            for (int i = 0; i < 4; i++)
            {
                var a = new byte[4];  
                var b = new byte[4];  
                for (var j = 0; j < 4; j++)
                {
                    a[j] = s[j,i];
                    b[j] = (byte)(s[j,i] & 0x80) != 0 ? (byte)((s[j,i] << 1) ^ 0x011b) : (byte)(s[j,i] << 1);

                }
                s[i,0] = (byte) (b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]);
                s[i,1] = (byte) (a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]); 
                s[i,2] = (byte) (a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]); 
                s[i,3] = (byte) (a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]); 
            }
            return s;
        }
    }
}