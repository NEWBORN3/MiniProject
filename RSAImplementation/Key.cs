using System;
using System.Numerics;
using System.Runtime.Serialization;

namespace RSAImplementation
{
    [DataContract(Name = "Key", Namespace = "RSAImplementation")]
    [Serializable]
    public class Key
    {
        [DataMember(Name = "type")]
        public KeyType keyType;
        [DataMember(Name = "n")]
        public BigInteger n { get; set; }
        [DataMember(Name = "e")]
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