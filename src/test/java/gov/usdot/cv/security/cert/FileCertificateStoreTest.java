package gov.usdot.cv.security.cert;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.nio.file.Paths;
import java.text.ParseException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.BeforeClass;
import org.junit.Test;

import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

import gov.usdot.cv.security.clock.ClockHelperTest;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.msg.IEEE1609p2Message;
import gov.usdot.cv.security.msg.MessageException;
import gov.usdot.cv.security.util.UnitTestHelper;

public class FileCertificateStoreTest {
	static final private boolean isDebugOutput = false;
    
	private static final String certsValidDate = "Fri May 05 20:44:47 EDT 2017";
	
	private static final String certsFolder = "/etc/1609_sample_certs/certs/";
	private static final String pcaCert = "trustedcerts/pca";
	private static final String selfCert = "downloadFiles/0465676ec6d9c8c0.cert";
	private static final String selfCertPrivateKeyReconstructionValue = "downloadFiles/0465676ec6d9c8c0.s";
	private static final String clientCert = "downloadFiles/1ece38c9a40bf946.cert";
	private static final String clientCertPrivateKeyReconstructionValue = "downloadFiles/1ece38c9a40bf946.s";
	
	private static final String testString = "48656c6c6f20776f726c6421";
	private static final String encryptedTestString = "0381004003800c48656c6c6f20776f726c642140022fe100017f6592a50f508101010003018097e3682da8de6431508300000000001917119083279c80118c736cc53a9426ffff0101000187818288719fb921a47d02e57e759afa1688d02c721e062bc6928cb638cc6b7256d0438080403fae8a8a0f16f550a450ba143498c0c3210f3baec82797f62dfb9f9700bf436bbec3192a092bc2ff43f8d8b6d90b38897ffec39d5f0a89ff6808984e6ce41f";
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		ClockHelperTest.setNow(certsValidDate);
		CertificateManager.clear();
	}
	
	@Test
	public void testPublicCertificateLoad() throws DecoderException, CertificateException, IOException,
													CryptoException, DecodeFailedException, DecodeNotSupportedException,
													EncodeFailedException, EncodeNotSupportedException {
		FileCertificateStore.load(new CryptoProvider(), "PCA", Paths.get(certsFolder, pcaCert));
		CertificateWrapper cert = CertificateManager.get("PCA");
		assertNotNull(cert);
		assertNotNull(cert.getEncryptionPublicKey());
		assertNotNull(cert.getSigningPublicKey());
		assertNull(cert.getEncryptionPrivateKey());
		assertNull(cert.getSigningPrivateKey());
	}
	
	@Test
	public void testFullCertificateLoad() throws DecoderException, CertificateException, IOException,
													CryptoException, DecodeFailedException, DecodeNotSupportedException,
													EncodeFailedException, EncodeNotSupportedException {
		FileCertificateStore.load(new CryptoProvider(), 
		   CertificateWrapper.getSelfCertificateFriendlyName(), 
				Paths.get(certsFolder, selfCert),
				Paths.get(certsFolder, selfCertPrivateKeyReconstructionValue));
		CertificateWrapper cert = CertificateManager.get("Self");
		assertNotNull(cert);
		assertNotNull(cert.getEncryptionPublicKey());
		assertNotNull(cert.getSigningPublicKey());
		assertNotNull(cert.getEncryptionPrivateKey());
		assertNotNull(cert.getSigningPrivateKey());
	}
	
	@Test
	public void testValidateAndLog() throws ParseException, DecoderException, CertificateException, IOException,
												CryptoException, MessageException, EncodeFailedException, EncodeNotSupportedException,
												DecodeFailedException, DecodeNotSupportedException, InvalidCipherTextException {
		CertificateManager.clear();
		CryptoProvider cryptoProvider = new CryptoProvider();
		FileCertificateStore.load(cryptoProvider, "PCA", Paths.get(certsFolder, pcaCert));
		FileCertificateStore.load(new CryptoProvider(), "Self", 
				Paths.get(certsFolder, selfCert),
				Paths.get(certsFolder, selfCertPrivateKeyReconstructionValue));
		FileCertificateStore.load(new CryptoProvider(), "Client", 
                Paths.get(certsFolder, clientCert),
                Paths.get(certsFolder, clientCertPrivateKeyReconstructionValue));
		
		decrypt(encryptedTestString, cryptoProvider);
		encrypt(testString, cryptoProvider);

		CertificateManager.clear();
	}
	
	private void decrypt(String encryptedMessage, CryptoProvider cryptoProvider) throws DecoderException, MessageException, CertificateException,
																						CryptoException, EncodeFailedException, EncodeNotSupportedException {
		byte[] encryptedMessageBytes = Hex.decodeHex(encryptedMessage.toCharArray());
		IEEE1609p2Message msgRecv = IEEE1609p2Message.parse(encryptedMessageBytes, cryptoProvider);
		byte[] recvEncryptedMessage = msgRecv.getPayload();
		assertNotNull(recvEncryptedMessage);
	}
	
	private byte[] encrypt(String payloadString, CryptoProvider cryptoProvider) throws CertificateException, DecoderException,EncodeFailedException,
																						EncodeNotSupportedException, CryptoException {
		final int Psid = 0x2fe1;
		byte[] payloadBytes = Hex.decodeHex(payloadString.toCharArray());
		IEEE1609p2Message msg = new IEEE1609p2Message(cryptoProvider);
		msg.setPSID(Psid);
		return  msg.sign(payloadBytes);
	}
}
