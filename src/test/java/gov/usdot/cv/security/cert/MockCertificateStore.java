package gov.usdot.cv.security.cert;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EccP256CurvePoint;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSAProvider;
import gov.usdot.cv.security.util.Ieee1609dot2Helper;
import gov.usdot.cv.security.util.UnitTestHelper;

public class MockCertificateStore {

	static public void addTestCertificates() throws EncodeFailedException, EncodeNotSupportedException, NoSuchAlgorithmException, KeyStoreException, CryptoException, InvalidAlgorithmParameterException, CertificateException, IOException {
		addCertificates("PCA", "PCA-private");
		addCertificates("Self-public", "Self-private");
		addCertificates("Client-public", "Client-private");
	}

	static public void addCertificates(String publicCertificateName, String privateCertificateName)
			throws EncodeFailedException, EncodeNotSupportedException, NoSuchAlgorithmException, KeyStoreException, CryptoException, InvalidAlgorithmParameterException, CertificateException, IOException {
		CertificateWrapper[] certificates = createCertificates();
		CertificateManager.put(privateCertificateName, certificates[0]);
		CertificateManager.put(publicCertificateName, certificates[1]);
	}

	static public CertificateWrapper[] createCertificates() throws EncodeFailedException, EncodeNotSupportedException, NoSuchAlgorithmException, KeyStoreException, CryptoException, InvalidAlgorithmParameterException, CertificateException, IOException {
		CryptoProvider cryptoProvider = new CryptoProvider();
		MockCertificate privateCertificate = new MockCertificate(cryptoProvider);
		MockCertificate publicCertificate = new MockCertificate(privateCertificate);
		return new MockCertificate[] { privateCertificate, publicCertificate };
	}

	public static class MockCertificate extends CertificateWrapper {

		protected boolean isPrivateCertificate;
		protected final ECDSAProvider ecdsaProvider;

		/**
		 * Create private mock certificate
		 * 
		 * @param cryptoProvider
		 *            to use for certificate generation
		 * @throws NoSuchAlgorithmException 
		 * @throws KeyStoreException 
		 * @throws CryptoException 
		 * @throws IOException 
		 * @throws java.security.cert.CertificateException 
		 * @throws InvalidAlgorithmParameterException 
		 */
		protected MockCertificate(CryptoProvider cryptoProvider) throws NoSuchAlgorithmException, KeyStoreException, CryptoException, InvalidAlgorithmParameterException, java.security.cert.CertificateException, IOException
 {
			super(cryptoProvider);
			isPrivateCertificate = true;
			ecdsaProvider = cryptoProvider.getECDSAProvider();

			signingPrivateKey = UnitTestHelper.createUnsecurePrivateKey(UnitTestHelper.inMemoryKeyStore());
			signingPublicKey = (ECPublicKeyParameters) ecdsaProvider.generateKeyPair().getPublic();

			encryptionPrivateKey = UnitTestHelper.createUnsecurePrivateKey(UnitTestHelper.inMemoryKeyStore());
			encryptionPublicKey = (ECPublicKeyParameters) ecdsaProvider.generateKeyPair().getPublic();
		}

		/**
		 * Create public mock certificate from a private certificate
		 * 
		 * @param privateCertificate
		 *            to copy public keys from
		 * @throws EncodeNotSupportedException
		 * @throws EncodeFailedException
		 */
		protected MockCertificate(MockCertificate privateCertificate)
				throws EncodeFailedException, EncodeNotSupportedException {
			super(privateCertificate.cryptoProvider);
			isPrivateCertificate = false;
			ecdsaProvider = privateCertificate.ecdsaProvider;
			encryptionPublicKey = privateCertificate.getEncryptionPublicKey();
			signingPublicKey = privateCertificate.getSigningPublicKey();
		}

		/**
		 * Create mock certificate from serialized bytes
		 * 
		 * @param cryptoProvider
		 *            to assign to this certificate
		 * @param byteBuffer
		 *            bytes to serialize from
		 * @throws CertificateException
		 * @throws EncodeNotSupportedException
		 * @throws EncodeFailedException
		 * @throws CryptoException 
		 * @throws gov.usdot.cv.security.cert.CertificateException 
		 */
		protected MockCertificate(CryptoProvider cryptoProvider, byte[] bytes)
				throws CertificateException, EncodeFailedException, EncodeNotSupportedException, CryptoException, gov.usdot.cv.security.cert.CertificateException {
			super(cryptoProvider);
			ecdsaProvider = cryptoProvider.getECDSAProvider();
			CertificateWrapper cert = CertificateWrapper.fromBytes(cryptoProvider, bytes);
			isPrivateCertificate = cert.getSigningPrivateKey() != null;
			if (isPrivateCertificate) {
				signingPrivateKey = cert.getSigningPrivateKey();
				encryptionPrivateKey = cert.getEncryptionPrivateKey();
			}
			signingPublicKey = cert.getSigningPublicKey();
			encryptionPublicKey = cert.getEncryptionPublicKey();
		}

		/**
		 * Serializes mock certificate to bytes
		 * 
		 * @throws CryptoException
		 */
		@Override
		public byte[] getBytes() {
			final byte certCount = (byte) (isPrivateCertificate ? 4 : 2);
			ByteBuffer bb = ByteBuffer.allocate(1 + (ECDSAProvider.ECDSAPublicKeyEncodedLength) * certCount);
			bb.put(certCount);
			if (isPrivateCertificate) {
				ecdsaProvider.encodePrivateKey(bb, (ECPrivateKey) signingPrivateKey.getKey());
				ecdsaProvider.encodePrivateKey(bb, (ECPrivateKey) encryptionPrivateKey.getKey());
			}

			try {
				EccP256CurvePoint encodedSigningPublicKey = ecdsaProvider.encodePublicKey(signingPublicKey);
				EccP256CurvePoint encodedEncryptionPublicKey = ecdsaProvider.encodePublicKey(encryptionPublicKey);

				bb.put(Ieee1609dot2Helper.encodeCOER(encodedSigningPublicKey));
				bb.put(Ieee1609dot2Helper.encodeCOER(encodedEncryptionPublicKey));
			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}

			return Arrays.copyOfRange(bb.array(), 0, bb.position());
		}

		@Override
		public boolean isValid() {
			return true;
		}

		@Override
		public Date getExpiration() {
			final long thisTimeNextWeek = System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 7;
			return new Date(thisTimeNextWeek);
		}
	}

}
