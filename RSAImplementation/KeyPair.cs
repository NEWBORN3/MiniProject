using System;
using System.Runtime.Serialization;

namespace RSAImplementation
{
    [DataContract]
    [Serializable]
    public class KeyPair
    {
        [DataMember]
        public readonly Key privateKey;
        [DataMember]
        public readonly Key publicKey;

        public KeyPair(Key _publicKey, Key _privateKey)
        {
            publicKey = _publicKey;
            privateKey = _privateKey;
        }
    }
}