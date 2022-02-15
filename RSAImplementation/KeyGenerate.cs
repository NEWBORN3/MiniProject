using System;
using System.Numerics;
namespace RSAImplementation
{
    public class KeyGenerate
    {
        const int e = 0x10001; //65537
        public static BigInteger p, q, n, x, d = new BigInteger();
        public KeyPair GenerateKey(int bitlength)
        {
            do
            {
                q = RandomPrimeNumber(bitlength / 2);
            } while (q % e == 1);
            do
            {
                p = RandomPrimeNumber(bitlength / 2);
            } while (p % e == 1);

            n = q * p;
            x = (p - 1) * (q - 1);

          
            d = ModularInverse(e, x);

            Key publicKey = new Key(n);
            Key privateKey = new Key(d, n);

            return new KeyPair(publicKey, privateKey);
        }

        public static BigInteger RandomPrimeNumber(int bitlength)
        {
             if (bitlength%8 != 0)
            {
                throw new Exception("Invalid bit length for key given, cannot generate primes.");
            }

            byte[] randBytes = new byte[(bitlength / 8)+1];
            Random rand = new Random(DateTime.UtcNow.Millisecond);

            rand.NextBytes(randBytes);
            randBytes[randBytes.Length - 1] = 0x0; //unsigned

            //infinte loop
            SetBitInByte(0, ref randBytes[0]);
            SetBitInByte(7, ref randBytes[randBytes.Length - 2]);
            SetBitInByte(6, ref randBytes[randBytes.Length - 2]);
            while (true)
            {
                //Performing a Rabin-Miller primality test.
                bool isPrime = RabinMillerTest(randBytes, 40);
                if (isPrime)
                {
                    break;
                }
                else
                {
                    IncrementByteArrayLE(ref randBytes, 2);
                    var upper_limit = new byte[randBytes.Length];
                    upper_limit[randBytes.Length - 1] = 0x0;
                    BigInteger upper_limit_bi = new BigInteger(upper_limit);
                    BigInteger lower_limit = upper_limit_bi - 20;
                    BigInteger current = new BigInteger(randBytes);

                    if (lower_limit < current && current < upper_limit_bi)
                    {
                        return new BigInteger(-1);
                    }
                }
            }

            return new BigInteger(randBytes);
        }

        public static void SetBitInByte(int bitNumFromRight, ref byte toSet)
        {
            byte mask = (byte)(1 << bitNumFromRight);
            toSet |= mask;
        }
        public static bool RabinMillerTest(byte[] bSource, int certainty)
        {
            BigInteger source = new BigInteger(bSource);

            if (source == 2 || source == 3)
            {
                return true;
            }

            if (source < 2 || source % 2 == 0)
            {
                return false;
            }


            BigInteger d = source - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }


            Random rng = new Random(Environment.TickCount);
            byte[] bytes = new byte[source.ToByteArray().LongLength];
            BigInteger a;


            for (int i = 0; i < certainty; i++)
            {
                do
                {

                    rng.NextBytes(bytes);
                    a = new BigInteger(bytes);
                }
                while (a < 2 || a >= source - 2);


                BigInteger x = BigInteger.ModPow(a, d, source);
                if (x == 1 || x == source - 1)
                {
                    continue;
                }


                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, source);
                    if (x == 1)
                    {
                        return false;
                    }
                    else if (x == source - 1)
                    {
                        break;
                    }
                }

                if (x != source - 1)
                {
                    return false;
                }
            }
            return true;
        }

        public static BigInteger ModularInverse(BigInteger u, BigInteger v)
        {

            BigInteger inverse, u1, u3, v1, v3, t1, t3, q = new BigInteger();

            BigInteger iteration;


            u1 = 1;
            u3 = u;
            v1 = 0;
            v3 = v;


            iteration = 1;
            while (v3 != 0)
            {

                q = u3 / v3;
                t3 = u3 % v3;
                t1 = u1 + q * v1;


                u1 = v1; v1 = t1; u3 = v3; v3 = t3;
                iteration = -iteration;
            }

            if (u3 != 1)
            {

                return 0;
            }
            else if (iteration < 0)
            {
                inverse = v - u1;
            }
            else
            {
                inverse = u1;
            }


            return inverse;
        }

        public static void IncrementByteArrayLE(ref byte[] randomBytes, int amt)
        {
            BigInteger n = new BigInteger(randomBytes);
            n += amt;
            randomBytes = n.ToByteArray();
        }
    }

}