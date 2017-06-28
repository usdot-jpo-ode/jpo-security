package gov.usdot.cv.security.crypto;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.oss.asn1.AbstractData;
import com.oss.asn1.ControlTableNotFoundException;
import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;
import com.oss.asn1.InitializationException;

import gov.usdot.asn1.generated.ieee1609dot2.Ieee1609dot2;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2.Certificate;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EccP256CurvePoint;
import gov.usdot.cv.security.util.ByteArrayHelper;
import gov.usdot.cv.security.util.Ieee1609dot2Helper;

public class AsymmetricKeysTest {
	
	private ECKeyPairGenerator ecdsaKeyGenerator;
	private ECCurve ecdsaEllipticCurve;
	private ECDomainParameters ecdsaDomainParameters;
	
	static private final byte[] derivation = ByteBuffer.allocate(8).putLong(0xdeadbeefcafebabeL).array();
	static private final byte[] encoding   = ByteBuffer.allocate(8).putLong(0xebabefacfeebdaedL).array();
	private CipherParameters iesParameters;
	private IESEngine iesEngine;
	
	public static final int ECDSAPublicKeyEncodedLength = 33;
	private static final byte[] nullPublicKey = new byte[ECDSAPublicKeyEncodedLength];
	
	private static final String signingPrivateKeySeed = "4cfb69ebfea42814116ca752416fb2bc5a8b20e7195ef96bff89ad4cd2567986";
	private static final String cert  = "0003018097e3682da8de6431508300000000001917119083279c80118c736cc53a9426ffff0101000187818288719fb921a47d02e57e759afa1688d02c721e062bc6928cb638cc6b7256d043";
    private static final String certPrivateKeyReconstructionValue = "701b753e785e68a4b0976e4afb2af0471065efa1d6021334ffa790331d6bfdfe";
    private static final String pca  = "80030080fabd443dbf8585fa5981197632787063617273652d746573742e6768736973732e636f6d5e6f5b0002190f14c186000a83010380007c8001e4800348010180012380038500010101008001060001260001800001818001828001050290010490ffff010490ffff020490ffff030490ffff04000183000187008083e7255472518727263f9d3d7f5f7f819baf10771bfadfdc75326778f7bd0c7a8a8080832e142f1875e9947357cc4062b2d0f63b293c935bb242aa0c2ca5470df8ac1be98080a20d86ab6c94a0deaa7353cb9eaabe5275613fcfc55e5d26648b1ce17ebdae2b5041ddb5bc4967b72909b127be83e9932f023532c7041d023fe92121cd310b01";
    
    private static final byte[] clearTextIn = "Hello World!".getBytes();
	
	@Before
	public void setUp() {
		X9ECParameters curveX9ECParameters = NISTNamedCurves.getByName("P-256");
		ecdsaEllipticCurve = curveX9ECParameters.getCurve();
		ecdsaDomainParameters = new ECDomainParameters(
				ecdsaEllipticCurve, curveX9ECParameters.getG(), curveX9ECParameters.getN(), curveX9ECParameters.getH());
		ECKeyGenerationParameters ecdsaKeyGenParameters = new ECKeyGenerationParameters(
				ecdsaDomainParameters, CryptoProvider.getSecureRandom());
		ecdsaKeyGenerator = new ECKeyPairGenerator();
		ecdsaKeyGenerator.init(ecdsaKeyGenParameters);
		
		
		iesParameters = new IESWithCipherParameters(derivation, encoding, 128, 128);
		iesEngine = new IESEngine(new ECDHCBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()), new HMac(new SHA256Digest()));
	}
	
	@Test
	public void TestGeneratedAsymmetricKeys() throws InvalidCipherTextException {
		System.out.println("=========================================================================");
		
		try {
			System.out.println("Starting test with generated keys.");
			System.out.println();
			
			// Generate Asymmetric key pair to test with guarnteed working key pair
			AsymmetricCipherKeyPair generatedCertKeyPair = ecdsaKeyGenerator.generateKeyPair();
			ECPublicKeyParameters generatedCertPublicKey = (ECPublicKeyParameters) generatedCertKeyPair.getPublic();
			ECPrivateKeyParameters generatedCertPrivateKey = (ECPrivateKeyParameters) generatedCertKeyPair.getPrivate();
			
			System.out.println("Generated certificate public key Q: " + generatedCertPublicKey.getQ().toString());
			System.out.println("Generated certificate private key D: " + generatedCertPrivateKey.getD().toString());
			System.out.println();
			
			// Generate Ephemeral Key as per standard 
			AsymmetricCipherKeyPair ephemeralKeyPair = ecdsaKeyGenerator.generateKeyPair();
			ECPublicKeyParameters ephemeralPublicKey = (ECPublicKeyParameters) ephemeralKeyPair.getPublic();
			ECPrivateKeyParameters ephemeralPrivateKey = (ECPrivateKeyParameters) ephemeralKeyPair.getPrivate();
	
			System.out.println("Generated ephemeral public key Q: " + ephemeralPublicKey.getQ().toString());
			System.out.println("Generated ephemeral private key D: " + ephemeralPrivateKey.getD().toString());
			System.out.println();
					
			// Encrypt
			byte[] cipherText = encrypt(clearTextIn, ephemeralPrivateKey, generatedCertPublicKey);
			
			// Decrypt
			byte[] clearTextOut = decrypt(cipherText, ephemeralPublicKey, generatedCertPrivateKey);

			Assert.assertArrayEquals(clearTextIn, clearTextOut);
			
			System.out.println("Generated keys test successful.");
		} catch(Exception e) {
			System.out.println("Test failed with exception:");
			e.printStackTrace();
		}

		System.out.println("=========================================================================");
		System.out.println();
	}
	
	@Test
	public void TestCertificateAsymmetricKeys() throws Exception {
		System.out.println("=========================================================================");
		
		try {
			System.out.println("Starting test with reconstructed keys.");
			System.out.println();
			
			// Read in the certificates' bytes and decode into Certificate instances		
			byte[] certBytes = Hex.decodeHex(cert.toCharArray());
			byte[] certPrivateKeyReconstructionValueBytes = Hex.decodeHex(certPrivateKeyReconstructionValue.toCharArray());
			byte[] signigngPrivateKeySeedBytes = Hex.decodeHex(signingPrivateKeySeed.toCharArray());
			
			Certificate certificate = decodeCOER(certBytes, new Certificate());
			
			System.out.println("Certificate decoded to:");
			System.out.println(certificate);
	
			byte[] pcaBytes = Hex.decodeHex(pca.toCharArray());
			Certificate pcaCertificate = decodeCOER(pcaBytes, new Certificate());
			
			System.out.println("PCA Certificate decoded to:");
			System.out.println(pcaCertificate);
			
			// Reconstruct the public and private keys based on the certificates
			ECPublicKeyParameters certificatePublicKey = reconstructImplicitPublicKey(pcaCertificate, certificate);
			ECPrivateKeyParameters certificatePrivateKey = 
								reconstructImplicitPrivateKey(pcaCertificate, certificate, certPrivateKeyReconstructionValueBytes, signigngPrivateKeySeedBytes);
	
			System.out.println("Reconstructed certificate public key Q: " + certificatePublicKey.getQ().toString());
			System.out.println("Reconstructed certificate private key D: " + certificatePrivateKey.getD().toString());
			System.out.println();
	
			// Generate Ephemeral Key as per standard 
			AsymmetricCipherKeyPair ephemeralKeyPair = ecdsaKeyGenerator.generateKeyPair();
			ECPublicKeyParameters ephemeralPublicKey = (ECPublicKeyParameters) ephemeralKeyPair.getPublic();
			ECPrivateKeyParameters ephemeralPrivateKey = (ECPrivateKeyParameters) ephemeralKeyPair.getPrivate();
	
			System.out.println("Generated ephemeral public key Q: " + ephemeralPublicKey.getQ().toString());
			System.out.println("Generated ephemeral private key D: " + ephemeralPrivateKey.getD().toString());
			System.out.println();
			
			// Encrypt
			byte[] cipherText = encrypt(clearTextIn, ephemeralPrivateKey, certificatePublicKey);
			
			// Decrypt
			byte[] clearTextOut = decrypt(cipherText, ephemeralPublicKey, certificatePrivateKey);
			
			Assert.assertArrayEquals(clearTextIn, clearTextOut);
			
			System.out.println("Reconstructed keys test successful.");
		} catch(Exception e) {
			System.out.println("Test failed with exception:");
			e.printStackTrace();
		}

		System.out.println("=========================================================================");
		System.out.println();
	}
	
	@Test
	public void TestUsing() throws Exception {
		System.out.println("=========================================================================");
		
		try {
			System.out.println("Starting test with reconstructed keys.");
			System.out.println();
			
			// Read in the certificates' bytes and decode into Certificate instances		
			byte[] certBytes = Hex.decodeHex(cert.toCharArray());
			byte[] certPrivateKeyReconstructionValueBytes = Hex.decodeHex(certPrivateKeyReconstructionValue.toCharArray());
			byte[] signigngPrivateKeySeedBytes = Hex.decodeHex(signingPrivateKeySeed.toCharArray());
			
			Certificate certificate = decodeCOER(certBytes, new Certificate());
			
			System.out.println("Certificate decoded to:");
			System.out.println(certificate);
	
			byte[] pcaBytes = Hex.decodeHex(pca.toCharArray());
			Certificate pcaCertificate = decodeCOER(pcaBytes, new Certificate());
			
			System.out.println("PCA Certificate decoded to:");
			System.out.println(pcaCertificate);
			
			// Reconstruct the public and private keys based on the certificates
			ECPublicKeyParameters certificatePublicKey = reconstructImplicitPublicKey(pcaCertificate, certificate);
			ECPrivateKeyParameters certificatePrivateKey = 
								reconstructImplicitPrivateKey(pcaCertificate, certificate, certPrivateKeyReconstructionValueBytes, signigngPrivateKeySeedBytes);
	
			System.out.println("Reconstructed certificate public key Q: " + certificatePublicKey.getQ().toString());
			System.out.println("Reconstructed certificate private key D: " + certificatePrivateKey.getD().toString());
			System.out.println();
	
			// Generate Ephemeral Key as per standard 
			AsymmetricCipherKeyPair ephemeralKeyPair = ecdsaKeyGenerator.generateKeyPair();
			ECPublicKeyParameters ephemeralPublicKey = (ECPublicKeyParameters) ephemeralKeyPair.getPublic();
			ECPrivateKeyParameters ephemeralPrivateKey = (ECPrivateKeyParameters) ephemeralKeyPair.getPrivate();
	
			System.out.println("Generated ephemeral public key Q: " + ephemeralPublicKey.getQ().toString());
			System.out.println("Generated ephemeral private key D: " + ephemeralPrivateKey.getD().toString());
			System.out.println();
			
			// Encrypt
			byte[] cipherText = encrypt(clearTextIn, ephemeralPrivateKey, certificatePublicKey);
			
			// Decrypt
			byte[] clearTextOut = decrypt(cipherText, ephemeralPublicKey, certificatePrivateKey);
			
			Assert.assertArrayEquals(clearTextIn, clearTextOut);
			
			System.out.println("Reconstructed keys test successful.");
		} catch(Exception e) {
			System.out.println("Test failed with exception:");
			e.printStackTrace();
		}

		System.out.println("=========================================================================");
		System.out.println();
	}
	
	public byte[] encrypt(byte[] clearText, ECPrivateKeyParameters ephemeralPrivateKey, ECPublicKeyParameters certificatePublicKey)
																	throws InvalidCipherTextException {
		System.out.println("Encrypting clear text '" + Hex.encodeHexString(clearText) + "'");
		
		iesEngine.init(true, ephemeralPrivateKey, certificatePublicKey, iesParameters);
		byte[] cipherText = iesEngine.processBlock(clearText, 0, clearText.length);
		
		System.out.println("Clear text encrypted to '" + Hex.encodeHexString(cipherText) + "'");
		System.out.println();
		
		return cipherText;
	}
	
	public byte[] decrypt(byte[] cipherText, ECPublicKeyParameters ephemeralPublicKey, ECPrivateKeyParameters certificatePrivateKey)
																	throws InvalidCipherTextException {
		System.out.println("Decrypting cipher text '" + Hex.encodeHexString(cipherText) + "'");
		
		iesEngine.init(false, certificatePrivateKey, ephemeralPublicKey, iesParameters);
		byte[] clearText = iesEngine.processBlock(cipherText, 0, cipherText.length);
		
		System.out.println("Cipher text decrypted to '" + Hex.encodeHexString(clearText) + "'");
		System.out.println();
		
		return clearText;
	}
	
	public ECPublicKeyParameters reconstructImplicitPublicKey(
											Certificate issuerCert, Certificate certificate)
																	throws EncodeFailedException, EncodeNotSupportedException {
		System.out.println("Reconstructing implicit public key:");
		
		if (certificate == null) {
			System.out.println("Invalid parameter: certificate can not be null");
			return null;
		}
		
		// The operation is QU = e*PU + QCA
		//     PU is the reconstruction key of CertU (the subordinate cert)
		//     QCA is the public key of the CA
		//     e = Hn(CertU).
		//         Hn(CertU) is defined in 1609.2-2016 Section 5.3.2 to be:
		//         Hash (ToBeSignedCertificate from the subordinate certificate) || Hash (Entirety of issuer certificate)
		
		// Get PU
		EccP256CurvePoint reconstructionKeyValue = certificate.getToBeSigned().getVerifyKeyIndicator().getReconstructionValue();
		ECPublicKeyParameters PU = decodePublicKey(reconstructionKeyValue);
		
		System.out.println("\tReconstruction key value from certificate: " + reconstructionKeyValue);
		
		System.out.println("\tPU Q= " + PU.getQ().toString() + "");
		
		// Get e
    	byte[] tbsBytes = Ieee1609dot2Helper.encodeCOER(certificate.getToBeSigned());
    	byte[] tbsHash = computeDigest(tbsBytes, 0, tbsBytes.length);
    	
    	byte[] issuerCertBytes = Ieee1609dot2Helper.encodeCOER(issuerCert);
    	byte[] issuerCertHash = computeDigest(issuerCertBytes, 0, issuerCertBytes.length);
    	
    	byte[] eInput = ByteArrayHelper.concat(tbsHash, issuerCertHash);
		byte[] eBytes = computeDigest(eInput, 0, eInput.length);
		
		BigInteger e = new BigInteger(1, eBytes);
		
		System.out.println("\te = " + e);
    	
		// Get QCA
		ECPoint QCA = decodePublicKey(issuerCert.getToBeSigned().getVerifyKeyIndicator().getVerificationKey().getEcdsaNistP256()).getQ();
		
		System.out.println("\tQCA = " + QCA);
		
		// Calculate QU = e*PU + QCA
    	ECPoint QU = PU.getQ().multiply(e).add(QCA);
    	
    	System.out.println("\tQU = " + QU);
		
		System.out.println("Public key reconstruction complete.");
		System.out.println();
    	
    	return new ECPublicKeyParameters(QU, ecdsaDomainParameters);
	}
	
	public ECPrivateKeyParameters reconstructImplicitPrivateKey(
											Certificate issuerCert, Certificate certificate,
											byte[] reconstructionKeyValueBytes, byte[] seedPrivateKeyBytes)
																	throws EncodeFailedException, EncodeNotSupportedException {
		System.out.println("Reconstructing implicit private key:");
		
		// The operation is du = r + e*k 
		//     r is the reconstruction value
		//     k is the seed private
		//     e = Hn(CertU).
		//         Hn(CertU) is defined in 1609.2-2016 Section 5.3.2 to be:
		//         Hash (ToBeSignedCertificate from the subordinate certificate) || Hash (Entirety of issuer certificate)
		
		// Get r
		BigInteger r = new BigInteger(1, reconstructionKeyValueBytes);
		
		System.out.println("\tr = " + r);
		
		// Get e
    	byte[] tbsBytes = Ieee1609dot2Helper.encodeCOER(certificate.getToBeSigned());
    	byte[] tbsHash = computeDigest(tbsBytes, 0, tbsBytes.length);
    
    	byte[] issuerCertBytes = Ieee1609dot2Helper.encodeCOER(issuerCert);
    	byte[] issuerCertHash = computeDigest(issuerCertBytes, 0, issuerCertBytes.length);
    	
    	byte[] eInput = ByteArrayHelper.concat(tbsHash, issuerCertHash);
		byte[] eBytes = computeDigest(eInput, 0, eInput.length);
		
		BigInteger e = new BigInteger(1, eBytes);
		
		System.out.println("\te = " + e);
		
		// Get k
		BigInteger k = new BigInteger(seedPrivateKeyBytes);
		
		System.out.println("\tk = " + k);
		
		// Calculate du = r + e*k
		BigInteger du = r.add(e.multiply(k));
		
		System.out.println("\tdu = " + du);
		
		System.out.println("Private key reconstruction complete.");
		System.out.println();
		
		return new ECPrivateKeyParameters(du, ecdsaDomainParameters);
	}
	
	public ECPublicKeyParameters decodePublicKey(EccP256CurvePoint publicKey) {
		if (publicKey == null) {
			System.out.println("Invalid parameter: publicKey should not be null");
			return null;
		}
		
		byte[] publicKeyBytes = null;
		if (publicKey.hasX_only()) {
			publicKeyBytes = publicKey.getX_only().byteArrayValue();
		}
		else if(publicKey.hasCompressed_y_0()) {
			publicKeyBytes = publicKey.getCompressed_y_0().byteArrayValue();
		}
		else if(publicKey.hasCompressed_y_1()) {
			publicKeyBytes = publicKey.getCompressed_y_1().byteArrayValue();
		}
		else if(publicKey.hasUncompressed()) {
			// Concatenate the uncompressed x & y
			publicKeyBytes = ByteArrayHelper.concat(publicKey.getUncompressed().getX().byteArrayValue(),
									publicKey.getUncompressed().getY().byteArrayValue());
		}
		else {
			System.out.println(String.format("Unexpected EccP256CurvePoint Type value %d", publicKey.getChosenFlag()));
		}

		// The Bouncy Castle ECPublicKeyParameters expects a flag byte at the beginning
		// indicating which compression algorithm, if any, is used for the y-coordinate
		byte publicKeyAlgorithm = (byte)(publicKey.getChosenFlag()-1);
		publicKeyBytes = ByteArrayHelper.prepend(publicKeyAlgorithm, publicKeyBytes);
		
		return (!Arrays.areEqual(publicKeyBytes, nullPublicKey)) ?
					(new ECPublicKeyParameters(ecdsaEllipticCurve.decodePoint(publicKeyBytes), ecdsaDomainParameters)) :
					(null);
	}
	
	public byte[] computeDigest(byte[] bytes, int start, int length ) {
		if ( bytes == null )
			return null;
		SHA256Digest digestProvider = new SHA256Digest();
		digestProvider.reset();
		digestProvider.update(bytes, start, length);
		byte[] digest = new byte[digestProvider.getDigestSize()];
		digestProvider.doFinal(digest, 0);
		return digest;
	}
	
	public static <T extends AbstractData> T decodeCOER(byte[] bytes, T dataType) 
												throws DecodeFailedException, DecodeNotSupportedException {
		ByteArrayInputStream bytesStream = new ByteArrayInputStream(bytes);
		T data = (T)Ieee1609dot2.getCOERCoder().decode(bytesStream, dataType);
		
		return data;
	}
	
	static {
		try {
			Ieee1609dot2.initialize();
		} catch (ControlTableNotFoundException e) {
			System.out.println("Failed to initiliaze Ieee1609dot2 environment ");
			e.printStackTrace();
		} catch (InitializationException e) {
			System.out.println("Failed to initiliaze Ieee1609dot2 environment ");
			e.printStackTrace();
		}
	}
}
