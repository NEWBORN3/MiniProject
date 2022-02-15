using System;

namespace AESImplementation
{
    public static class Utility
    {
        public static T[] Slice<T>(this T[] source, int start, int end)
        {
            // Handles negative ends.
            if (end < 0)
            {
                end = source.Length + end;
            }
            int len = end - start;

            // Return new array.
            T[] res = new T[len];
            for (int i = 0; i < len; i++)
            {
                res[i] = source[i + start];
            }
            return res;
        }

        public static byte[] GenerateRandomByte(int byteSize)
        {
            Random rnd = new Random();
            byte[] b = new byte[byteSize]; 
            rnd.NextBytes(b);
            return b;
        }
    }
}