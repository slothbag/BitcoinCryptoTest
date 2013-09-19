using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Parameters;
using System.IO;

namespace Bitcoin_Tool.Crypto
{
	public class ECKeyPair
	{
		ECDomainParameters ecParams = new ECDomainParameters(
			SecNamedCurves.GetByName("secp256k1").Curve, SecNamedCurves.GetByName("secp256k1").G, SecNamedCurves.GetByName("secp256k1").N);
		public Byte[] privKey { get; private set; }
		public Byte[] pubKey { get; private set; }
		public Boolean isCompressed { get; private set; }

		public ECKeyPair(Byte[] privKey, Byte[] pubKey, Boolean compressed)
		{
			this.privKey = privKey;
			if (pubKey != null)
			{
				this.pubKey = pubKey;
				this.isCompressed = pubKey.Length <= 33;
			}
			else
			{
				calcPubKey(compressed);
			}
		}

		public void compress(bool comp)
		{
			if (isCompressed == comp) return;
			ECPoint point = ecParams.Curve.DecodePoint(pubKey);
			if (comp)
				pubKey = compressPoint(point).GetEncoded();
			else
				pubKey = decompressPoint(point).GetEncoded();
			isCompressed = comp;
		}

		public Boolean verifySignature(Byte[] data, Byte[] sig)
		{
			ECDsaSigner signer = new ECDsaSigner();
			signer.Init(false, new ECPublicKeyParameters(ecParams.Curve.DecodePoint(pubKey), ecParams));
			using (Asn1InputStream asn1stream = new Asn1InputStream(sig))
			{
				Asn1Sequence seq = (Asn1Sequence)asn1stream.ReadObject();
				return signer.VerifySignature(data, ((DerInteger)seq[0]).PositiveValue, ((DerInteger)seq[1]).PositiveValue);
			}
		}

		public Byte[] signData(Byte[] data)
		{
			if (privKey == null)
				throw new InvalidOperationException();
			ECDsaSigner signer = new ECDsaSigner();
			signer.Init(true, new ECPrivateKeyParameters(new BigInteger(1, privKey), ecParams));
			BigInteger[] sig = signer.GenerateSignature(data);
			using (MemoryStream ms = new MemoryStream())
			using (Asn1OutputStream asn1stream = new Asn1OutputStream(ms))
			{
				DerSequenceGenerator seq = new DerSequenceGenerator(asn1stream);
				seq.AddObject(new DerInteger(sig[0]));
				seq.AddObject(new DerInteger(sig[1]));
				seq.Close();
				return ms.ToArray();
			}
		}
		private void calcPubKey(bool comp) {

			ECPoint point = ecParams.G.Multiply(new BigInteger(1, privKey));
			this.pubKey = point.GetEncoded();
			compress(comp);
		}

		private ECPoint compressPoint(ECPoint point)
		{
			return new FpPoint(ecParams.Curve, point.X, point.Y, true);
		}

		private ECPoint decompressPoint(ECPoint point)
		{
			return new FpPoint(ecParams.Curve, point.X, point.Y, false);
		}
		
		/*
		public byte[] signMessage(byte[] data) {
	        if (this.privKey == null)
	            throw new Exception("This ECKey does not have the private key necessary for signing.");
	        
	        byte[] magic = System.Text.Encoding.UTF8.GetBytes("Bitcoin Signed Message:\n");
	        byte[] completedata = new Byte[magic.Length+data.Length];
	        magic.CopyTo(completedata, 0);
	        data.CopyTo(completedata, magic.Length);
	                                                                                         
	        System.Security.Cryptography.SHA256 sha256 = new System.Security.Cryptography.SHA256Managed();
	        byte[] hash = sha256.ComputeHash(sha256.ComputeHash(completedata));
	        
			ECDsaSigner signer = new ECDsaSigner();
			signer.Init(true, new ECPrivateKeyParameters(new BigInteger(1, privKey), ecParams));
			BigInteger[] sig = signer.GenerateSignature(hash);
			
	        // Now we have to work backwards to figure out the recId needed to recover the signature.
	        int recId = -1;
	        for (int i = 0; i < 4; i++) {
	            ECKey k = ECKey.recoverFromSignature(i, sig, hash, isCompressed);
	            if (k != null && Arrays.equals(k.pub, pub)) {
	                recId = i;
	                break;
	            }
	        }
	        if (recId == -1)
	            throw new Exception("Could not construct a recoverable key. This should never happen.");
			
	        int headerByte = recId + 27 + (isCompressed ? 4 : 0);
	        byte[] sigData = new byte[65];  // 1 header + 32 bytes for R + 32 bytes for S
	        sigData[0] = (byte)headerByte;
	        sig[0].ToByteArray().CopyTo(sigData, 1);
	        sig[1].ToByteArray().CopyTo(sigData, 33);
	        return sigData;
	    }
		
		public static ECKeyPair recoverFromSignature(int recId, System.Security.Cryptography.ECDsa sig, System.Security.Cryptography.SHA256 message, bool compressed) {
			BigInteger n = this.ecParams.N;
			BigInteger i = BigInteger.valueOf((long) recId / 2);
			BigInteger x = sig.r.add(i.multiply(n));
			ECCurve.Fp curve = (ECCurve.Fp) ecParams.Curve;
			BigInteger prime = curve.getQ();
			if (x.compareTo(prime) >= 0) {
				return null;
			}
			ECPoint R = decompressKey(x, (recId & 1) == 1);
			if (!R.multiply(n).isInfinity())
				return null;
			BigInteger e = message.toBigInteger();
			BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
			BigInteger rInv = sig.r.modInverse(n);
			BigInteger srInv = rInv.multiply(sig.s).mod(n);
			BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
			ECPoint p1 = ecParams.getG().multiply(eInvrInv);
			ECPoint p2 = R.multiply(srInv);
			ECPoint.Fp q = (ECPoint.Fp) p2.add(p1);
			if (compressed) {
				q = new ECPoint.Fp(curve, q.getX(), q.getY(), true);
			}
			return new ECKeyPair((byte[])null, q.getEncoded());
		}
		
	    private static ECPoint decompressKey(BigInteger xBN, bool yBit) {
	        ECCurve.Fp curve = (ECCurve.Fp) ecParams.getCurve();
	        ECFieldElement x = new ECFieldElement.Fp(curve.getQ(), xBN);
	        ECFieldElement alpha = x.multiply(x.square().add(curve.getA())).add(curve.getB());
	        ECFieldElement beta = alpha.sqrt();
	        
	        if (beta == null)
	            throw new Exception("Invalid point compression");
	        if (beta.toBigInteger().testBit(0) == yBit) {
	            return new ECPoint.Fp(curve, x, beta, true);
	        } else {
	            ECFieldElement.Fp y = new ECFieldElement.Fp(curve.getQ(), curve.getQ().subtract(beta.toBigInteger()));
	            return new ECPoint.Fp(curve, x, y, true);
	        }
	    }
		
 		public static ECKey signedMessageToKey(String message, String signatureBase64) {
	        byte[] signatureEncoded;
	        try {
	            signatureEncoded = Base64.decode(signatureBase64);
	        } catch (RuntimeException e) {
	            throw new Exception("Could not decode base64", e);
	        }
	        if (signatureEncoded.length < 65)
	            throw new Exception("Signature truncated, expected 65 bytes and got " + signatureEncoded.length);
	        int header = signatureEncoded[0] & 0xFF;
	        if (header < 27 || header > 34)
	            throw new Exception("Header byte out of range: " + header);
	        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signatureEncoded, 1, 33));
	        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signatureEncoded, 33, 65));
	        ECDSASignature sig = new ECDSASignature(r, s);
	        byte[] messageBytes = Utils.formatMessageForSigning(message);
	        Sha256Hash messageHash = Sha256Hash.createDouble(messageBytes);
	        boolean compressed = false;
	        if (header >= 31) {
	            compressed = true;
	            header -= 4;
	        }
	        int recId = header - 27;
	        ECKey key = ECKey.recoverFromSignature(recId, sig, messageHash, compressed);
	        if (key == null)
	            throw new Exception("Could not recover public key from signature");
	        return key;
	    }

	    public void verifyMessage(String message, String signatureBase64)  {
	        ECKey key = ECKey.signedMessageToKey(message, signatureBase64);
	        if (!Arrays.equals(key.getPubKey(), pub))
	            throw new Exception("Signature did not match for message");
	    }
	    */
	}
}
