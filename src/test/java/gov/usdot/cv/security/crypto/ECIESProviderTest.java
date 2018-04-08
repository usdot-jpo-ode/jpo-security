package gov.usdot.cv.security.crypto;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EciesP256EncryptedKey;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.cert.CertificateWrapper;
import gov.usdot.cv.security.cert.MockCertificateStore;
import gov.usdot.cv.security.util.UnitTestHelper;

public class ECIESProviderTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(ECIESProviderTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		CryptoProvider.initialize();
		MockCertificateStore.addTestCertificates();
	}
	
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		CertificateManager.clear();
	}

	@Test
	public void testDirect() throws InvalidCipherTextException, CryptoException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, CertificateException, KeyStoreException, IOException {
		CryptoProvider cryptoProvider = new CryptoProvider();
		ECIESProvider eciesProvider = new ECIESProvider(cryptoProvider);
				KeyParameter symmetricKey = AESProvider.generateKey();
		assertNotNull(symmetricKey);
		log.debug(Hex.toHexString(symmetricKey.getKey()));
		AsymmetricCipherKeyPair recipientECCKey = cryptoProvider.getECDSAProvider().generateKeyPair();
		EciesP256EncryptedKey encodedKey = eciesProvider.encodeEciesP256EncryptedKey(symmetricKey, (ECPublicKeyParameters) recipientECCKey.getPublic());

		KeyParameter symmetricKey2 = eciesProvider.decodeEciesP256EncryptedKey(encodedKey, 
		      UnitTestHelper.createUnsecurePrivateKey(UnitTestHelper.inMemoryKeyStore()));
		assertNotNull(symmetricKey2);
		log.debug(Hex.toHexString(symmetricKey2.getKey()));
		assertTrue(Arrays.equals(symmetricKey.getKey(), symmetricKey2.getKey()));
	}
	
	@Test
	public void testUseCase() throws InvalidCipherTextException, CryptoException, EncodeFailedException, EncodeNotSupportedException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// sending side
		KeyParameter symmetricKey = AESProvider.generateKey();
		assertNotNull(symmetricKey);
		log.debug(Hex.toHexString(symmetricKey.getKey()));
		EciesP256EncryptedKey encodedKey = encode(symmetricKey);
		
		// receiving side
		KeyParameter symmetricKey2 = decode(encodedKey);
		assertNotNull(symmetricKey2);
		log.debug(Hex.toHexString(symmetricKey.getKey()));
		assertTrue(Arrays.equals(symmetricKey.getKey(), symmetricKey2.getKey()));
	}
	
	public EciesP256EncryptedKey encode(KeyParameter symmetricKey) throws InvalidCipherTextException, CryptoException,
																			EncodeFailedException, EncodeNotSupportedException {
		final String clientCertName = "Client-public";
		CertificateWrapper publicCert = CertificateManager.get(clientCertName);
		assertNotNull(publicCert);
		
		ECIESProvider eciesProvider = new CryptoProvider().getECIESProvider();

		return eciesProvider.encodeEciesP256EncryptedKey(symmetricKey, publicCert.getEncryptionPublicKey());
	}
	
	public KeyParameter decode(EciesP256EncryptedKey encodedKey) throws InvalidCipherTextException, CryptoException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		final String clientCertName = "Client-private";
		CertificateWrapper privateCert = CertificateManager.get(clientCertName);
		assertNotNull(privateCert);
		
		ECIESProvider eciesProvider = new CryptoProvider().getECIESProvider();
		
		assertNotNull(privateCert.getEncryptionPrivateKey());
		return eciesProvider.decodeEciesP256EncryptedKey(encodedKey, privateCert.getEncryptionPrivateKey());
	}
}
