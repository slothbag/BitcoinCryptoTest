using System;
using Bitcoin_Tool.Crypto;

namespace BitcoinCryptoTest
{
	class Program
	{
		public static void Main(string[] args)
		{
			PrivateKey privKey = new PrivateKey();
			Console.WriteLine(privKey.pubKey.address);
			
			string message = "Hello World!";
			byte[] messagedata = System.Text.Encoding.ASCII.GetBytes(message);
			
			//result should be 65 byte bitcoin style signature
			byte[] signature = privKey.SignMessage(messagedata);
			
			bool result = privKey.pubKey.VerifyMessage("Hello World!", signature);
			Console.WriteLine("Signature check: " + result);
			
			Console.Read();
		}
	}
}