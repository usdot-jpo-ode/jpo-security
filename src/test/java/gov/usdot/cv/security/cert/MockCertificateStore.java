package gov.usdot.cv.security.cert;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EccP256CurvePoint;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSAProvider;
import gov.usdot.cv.security.util.Ieee1609dot2Helper;

public class MockCertificateStore {

	static public void addTestCertificates() throws EncodeFailedException, EncodeNotSupportedException {
		addCertificates("PCA", "PCA-private");
		addCertificates("Self-public", "Self-private");
		addCertificates("Client-public", "Client-private");
	}

	static public void addCertificates(String publicCertificateName, String privateCertificateName)
			throws EncodeFailedException, EncodeNotSupportedException {
		CertificateWrapper[] certificates = createCertificates();
		CertificateManager.put(privateCertificateName, certificates[0]);
		CertificateManager.put(publicCertificateName, certificates[1]);
	}

	static public CertificateWrapper[] createCertificates() throws EncodeFailedException, EncodeNotSupportedException {
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
		 */
		protected MockCertificate(CryptoProvider cryptoProvider) {
			super(cryptoProvider);
			isPrivateCertificate = true;
			ecdsaProvider = cryptoProvider.getSigner();

			AsymmetricCipherKeyPair signingKeyPair = ecdsaProvider.generateKeyPair();
			signingKeyPair = (ECPrivateKeyParameters) signingKeyPair.getPrivate();
			signingPublicKey = (ECPublicKeyParameters) signingKeyPair.getPublic();

			AsymmetricCipherKeyPair encryptKeyPair = ecdsaProvider.generateKeyPair();
			encryptionKeyPair = (ECPrivateKeyParameters) encryptKeyPair.getPrivate();
			encryptionPublicKey = (ECPublicKeyParameters) encryptKeyPair.getPublic();
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
		 */
		protected MockCertificate(CryptoProvider cryptoProvider, byte[] bytes)
				throws CertificateException, EncodeFailedException, EncodeNotSupportedException {
			super(cryptoProvider);
			ecdsaProvider = cryptoProvider.getSigner();
			CertificateWrapper cert = CertificateWrapper.fromBytes(cryptoProvider, bytes);
			isPrivateCertificate = cert.getSigningKeyPair() != null;
			if (isPrivateCertificate) {
				signingKeyPair = cert.getSigningKeyPair();
				encryptionKeyPair = cert.getEncryptionPrivateKey();
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
				ecdsaProvider.encodePrivateKey(bb, signingKeyPair);
				ecdsaProvider.encodePrivateKey(bb, encryptionKeyPair);
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
