using System;
using System.Numerics;
using System.Runtime.Serialization;

namespace RSAImplementation
{
    
    public class Key
    {
  
        public KeyType keyType;
    
        public BigInteger n { get; set; }
    
        public int e = 0x10001;

        public readonly BigInteger d;

        public Key(BigInteger _d, BigInteger _n)
        {   
            n = _n;
            d = _d;
            keyType = KeyType.PRIVATE;
        }

        public Key(BigInteger n_)
        {
            n = n_;
            keyType = KeyType.PUBLIC;
        }

    }
}