package gov.usdot.cv.security.cert;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.apache.log4j.Logger;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoHelper;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.EcdsaP256SignatureWrapper;
import gov.usdot.cv.security.util.UnitTestHelper;

public class MockCertificateStoreTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(MockCertificateStoreTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		CryptoProvider.initialize();
	}

	@Before
	public void setUp() throws Exception {
		MockCertificateStore.addTestCertificates();
	}

	@After
	public void tearDown() throws Exception {
		CertificateManager.clear();
	}

	@Test
	public void testCreate() throws CryptoException {
		CryptoHelper helper = new CryptoHelper();
		
		final String pcaNamePrivate = "PCA-private";
		CertificateWrapper pcaPrivateCert = CertificateManager.get(pcaNamePrivate);
		assertNotNull(pcaPrivateCert);
		SecureECPrivateKey pcaSigningPrivateKey = pcaPrivateCert.getSigningPrivateKey();
		assertNotNull(pcaSigningPrivateKey);
		
		byte[] bytes = "Hello, World".getBytes();

		EcdsaP256SignatureWrapper signature = helper.computeSignature(bytes, pcaPrivateCert.getBytes(), 
		      pcaSigningPrivateKey);
		assertNotNull(signature);
		
		final String pcaNamePublic = "PCA";
		CertificateWrapper pcaPublicCert = CertificateManager.get(pcaNamePublic);
		assertNotNull(pcaPublicCert);
		
		ECPublicKeyParameters pcaSigningPublicKey = pcaPublicCert.getSigningPublicKey();
		assertNotNull(pcaSigningPublicKey);
		
		boolean isSignatureValid = helper.verifySignature(bytes, pcaPrivateCert.getBytes(), pcaSigningPublicKey, signature);
		log.debug("PCA Signature is valid: " + isSignatureValid);
		assertTrue(isSignatureValid);
		
		final String selfNamePublic = "Self-private";
		CertificateWrapper selfPublicCert = CertificateManager.get(selfNamePublic);
		assertNotNull(pcaPublicCert);
		
		ECPublicKeyParameters selfSigningPublicKey = selfPublicCert.getSigningPublicKey();
		assertNotNull(selfSigningPublicKey);
		
		isSignatureValid = helper.verifySignature(bytes, selfPublicCert.getBytes(), selfSigningPublicKey, signature);
		log.debug("Self Signature is valid: " + isSignatureValid);
		assertFalse(isSignatureValid);
	}
	
}
