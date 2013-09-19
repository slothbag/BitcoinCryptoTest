using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace Bitcoin_Tool.Crypto
{
	public class PrivateKey
	{
		private ECKeyPair ecKeyPair;
		public PublicKey pubKey { get; private set; }

		public PrivateKey()
		{
			Byte[] pk = new Byte[32];
			RandomNumberGenerator rng = new RNGCryptoServiceProvider();
			rng.GetBytes(pk);
			this.ecKeyPair = new ECKeyPair(pk, null, false);
			this.pubKey = new PublicKey(ecKeyPair);
		}

		public PrivateKey(Byte[] privKey, Boolean compress)
		{
			this.ecKeyPair = new ECKeyPair(privKey, null, compress);
			this.pubKey = new PublicKey(ecKeyPair);
		}

		public PrivateKey(ECKeyPair ecKeyPair)
		{
			if (ecKeyPair.privKey == null)
				throw new ArgumentException("ECKeyPair does not contain private key.");
			this.ecKeyPair = ecKeyPair;
			this.pubKey = new PublicKey(ecKeyPair);
		}

		public Byte[] ToBytes()
		{
			return ecKeyPair.privKey;
		}

		public Byte[] Sign(Byte[] data)
		{
			return ecKeyPair.signData(data);
		}
		
		public Byte[] SignMessage(byte[] data) {
			//return ecKeyPair.signMessage(data);
			return null;
		}
			

		public static PrivateKey FromWIF(String s)
		{
			Byte[] b = Base58CheckString.ToByteArray(s);
			if (b.Length == 0x20)
				return new PrivateKey(b, false);
			else if (b.Length == 0x21)
				return new PrivateKey(b.Take(0x20).ToArray(), true);
			else
				throw new ArgumentException("Invalid WIF Private Key");
		}

		public static PrivateKey FromBase64(String s, Boolean compress)
		{
			return new PrivateKey(Convert.FromBase64String(s), compress);
		}

		public static implicit operator PublicKey (PrivateKey k) {
			return k.pubKey;
		}

		public static implicit operator Address(PrivateKey k)
		{
			return k.pubKey.address;
		}
	}
}
