using System;
using System.Linq;

namespace Bitcoin_Tool.Crypto
{
	public class PublicKey
	{
		private ECKeyPair ecKeyPair;
		public Address address { get; private set; }

		public PublicKey(ECKeyPair ecKeyPair)
		{
			this.ecKeyPair = ecKeyPair;
			this.address = new Address(ecKeyPair.pubKey, 0xFF);
		}

		public Byte[] ToBytes()
		{
			return ecKeyPair.pubKey;
		}

		public Boolean VerifySignature(Byte[] data, Byte[] sig)
		{
			return ecKeyPair.verifySignature(data, sig);
		}
		
		public bool VerifyMessage(string message, Byte[] signature) {
			//ecKeyPair.verifyMessage(message, signature);
			return false;
		}

		public override bool Equals(object obj)
		{
			if (obj == null || !(obj is PublicKey))
				return false;
			return ((PublicKey)obj).ecKeyPair.pubKey.SequenceEqual(this.ecKeyPair.pubKey);
		}

		public override int GetHashCode()
		{
			return ecKeyPair.pubKey.GetHashCode();
		}

		public static implicit operator Address(PublicKey k)
		{
			return k.address;
		}
	}
}
