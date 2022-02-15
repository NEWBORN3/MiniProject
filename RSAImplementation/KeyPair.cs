using System;
using System.Runtime.Serialization;

namespace RSAImplementation
{
  
    public class KeyPair
    {
        
        public readonly Key privateKey;
        public readonly Key publicKey;

        public KeyPair(Key _publicKey, Key _privateKey)
        {
            publicKey = _publicKey;
            privateKey = _privateKey;
        }
    }
}