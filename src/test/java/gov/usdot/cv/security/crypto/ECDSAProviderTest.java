package gov.usdot.cv.security.crypto;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.BeforeClass;
import org.junit.Test;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EccP256CurvePoint;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.Signature;
import gov.usdot.cv.security.util.UnitTestHelper;

public class ECDSAProviderTest {
	
	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(ECDSAProviderTest.class);
	
	final static String dummySignerCertHex = "0003018097e3682da8de6431508300000000001917119083279c80118c736cc53a9426ffff0101000187818288719fb921a47d02e57e759afa1688d02c721e062bc6928cb638cc6b7256d043";
	static byte[] dummySignerCertBytes;
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		CryptoProvider.initialize();
		dummySignerCertBytes = Hex.decodeHex(dummySignerCertHex.toCharArray());
	}

	@Test
	public void testSignature() 
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, CryptoException, DecoderException {

		ECDSAProvider provider =  new CryptoProvider().getSigner();
		final byte[] message = "Hello, World!".getBytes();
		AsymmetricCipherKeyPair keyPair = provider.generateKeyPair();
		EcdsaP256SignatureWrapper signature = provider.computeSignature(message, dummySignerCertBytes, (ECPrivateKeyParameters)keyPair.getPrivate());
		boolean isSignatureValid = provider.verifySignature(message, dummySignerCertBytes, (ECPublicKeyParameters) keyPair.getPublic(), signature);
		log.debug("Is Signarure 1 Valid: " + isSignatureValid);
		assertTrue(isSignatureValid);
		final byte[] message2 = "Hello, World".getBytes();
		isSignatureValid = provider.verifySignature(message2, dummySignerCertBytes, (ECPublicKeyParameters) keyPair.getPublic(), signature);
		log.debug("Is Signarure 2 Valid: " + isSignatureValid);
		assertFalse(isSignatureValid);
		
		Signature encodedSignature = signature.encode();
		EcdsaP256SignatureWrapper signature2 = EcdsaP256SignatureWrapper.decode(encodedSignature, provider);
		isSignatureValid = provider.verifySignature(message, dummySignerCertBytes, (ECPublicKeyParameters) keyPair.getPublic(), signature2);
		log.debug("Is Signarure 3 Valid: " + isSignatureValid);
		assertTrue(isSignatureValid);
	}

	@Test
	public void testEncoding() throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		final byte[] data = "Hello, World!".getBytes();
		
		ECDSAProvider provider = new CryptoProvider().getSigner();
		AsymmetricCipherKeyPair keyPair = provider.generateKeyPair();
		ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.getPrivate();
		assertNotNull("Generated private key is not null", privateKey);
		ECPublicKeyParameters  publicKey  = (ECPublicKeyParameters) keyPair.getPublic();
		assertNotNull("Generated public key is not null", publicKey);
		
		final int maxByteBuffer = (1 << 16) - 1;
		ByteBuffer privateByteBuffer = ByteBuffer.allocate(maxByteBuffer);
		provider.encodePrivateKey(privateByteBuffer, privateKey);
		byte[] privateKeyBytes = (privateByteBuffer != null) ? (Arrays.copyOfRange(privateByteBuffer.array(), 0, privateByteBuffer.position())) : null;
		log.debug("Private key size: " + privateKeyBytes.length + ". Value: " + Hex.encodeHexString(privateKeyBytes));
		ECPrivateKeyParameters privateKey2 = provider.decodePrivateKey(privateKeyBytes);
		assertNotNull("Decoded private key is not null", privateKey2);
		
		EcdsaP256SignatureWrapper signature = provider.computeSignature(data, dummySignerCertBytes, privateKey);
		assertTrue( "Signed with original key. Signature valid with original key", provider.verifySignature(data, dummySignerCertBytes, publicKey, signature));
		
		signature = provider.computeSignature(data, dummySignerCertBytes, privateKey2);
		assertTrue( "Signed with decoded key. Signature valid with original key", provider.verifySignature(data, dummySignerCertBytes, publicKey, signature));
		
		EccP256CurvePoint encodedPublicKey = null;
		try {
			encodedPublicKey = provider.encodePublicKey(publicKey);
			assertTrue( "Public Key encoding succeeded",  true);
		} catch (CryptoException e) {
			assertTrue( "Public Key encoding succeeded",  false);
		}
		
		ECPublicKeyParameters publicKey2 = provider.decodePublicKey(encodedPublicKey);
		assertNotNull("Decoded public key is not null", publicKey2);
		
		signature = provider.computeSignature(data, dummySignerCertBytes, privateKey);
		assertTrue( "Signed with original key. Signature valid with original key", provider.verifySignature(data, dummySignerCertBytes, publicKey, signature));
		assertTrue( "Signed with original key. Signature valid with decoded key", provider.verifySignature(data, dummySignerCertBytes, publicKey2, signature));
		
		signature = provider.computeSignature(data, dummySignerCertBytes, privateKey2);
		assertTrue( "Signed with decoded key. Signature valid with original key", provider.verifySignature(data, dummySignerCertBytes, publicKey, signature));
		assertTrue( "Signed with decoded key. Signature valid with decoded key", provider.verifySignature(data, dummySignerCertBytes, publicKey2, signature));
	}
}
