package gov.usdot.cv.security.crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;
import com.oss.asn1.Null;
import com.oss.asn1.OctetString;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EccP256CurvePoint;
import gov.usdot.cv.security.cert.CertificateWrapper;
import gov.usdot.cv.security.util.ByteArrayHelper;
import gov.usdot.cv.security.util.Ieee1609dot2Helper;

/**
 * Helper provider that is used to create and verify ECDSA signatures 1609.2
 * signatures are ECDSA signatures of the SHA-256 hash of the message. The
 * resulting signature is an r-value (a random value used in generating the
 * signature) and an s-value (the resulting signature).
 */
public class ECDSAProvider {

   private static final Logger log = Logger.getLogger(ECDSAProvider.class);

   /**
    * Length of the encoded ECDSA public key in bytes
    */
   public static final int ECDSAPublicKeyEncodedLength = 33;

   /**
    * Length of the encoded ECDSA private key in bytes
    */
   public static final int ECDSAPrivateKeyEncodedLength = 32;

   private static final byte[] nullPublicKey = new byte[ECDSAPublicKeyEncodedLength];

   private final CryptoProvider cryptoProvider;
   private final ECDSASigner ecdsaSigner;
   private final ECKeyPairGenerator ecdsaKeyGenerator;
   private final ECCurve ecdsaEllipticCurve;
   private final ECDomainParameters ecdsaDomainParameters;

   /**
    * Instantiates ECDSA provider with new cryptographic provider
    */
   public ECDSAProvider() {
      this(new CryptoProvider());
   }

   /**
    * Instantiates ECDSA provider
    * 
    * @param cryptoProvider
    *           cryptographic provider to use
    */
   public ECDSAProvider(CryptoProvider cryptoProvider) {
      this.cryptoProvider = cryptoProvider;
      X9ECParameters curveX9ECParameters = NISTNamedCurves.getByName("P-256");
      ecdsaEllipticCurve = curveX9ECParameters.getCurve();
      ecdsaDomainParameters = new ECDomainParameters(ecdsaEllipticCurve, curveX9ECParameters.getG(),
            curveX9ECParameters.getN(), curveX9ECParameters.getH());
      ECKeyGenerationParameters ecdsaKeyGenParameters = new ECKeyGenerationParameters(ecdsaDomainParameters,
            CryptoProvider.getSecureRandom());
      ecdsaKeyGenerator = new ECKeyPairGenerator();
      ecdsaKeyGenerator.init(ecdsaKeyGenParameters);
      ecdsaSigner = new ECDSASigner();
   }

   /**
    * Computes wrapped message signature
    * 
    * @param toBeSignedDataBytes
    *           bytes of the ToBeSignedData
    * @param signingCertificateBytes
    *           bytes of the certificate performing the signing
    * @param signingPrivateKey
    *           private signing key to use
    * @return message signature
    */
   public EcdsaP256SignatureWrapper computeSignature(
      byte[] toBeSignedDataBytes,
      byte[] signingCertificateBytes,
      ECPrivateKeyParameters signingPrivateKey) {
      if (toBeSignedDataBytes == null || signingCertificateBytes == null) {
         return null;
      }

      byte[] inputHash = computeDigest(toBeSignedDataBytes, signingCertificateBytes);

      ecdsaSigner.init(true, new ParametersWithRandom(signingPrivateKey, CryptoProvider.getSecureRandom()));

      BigInteger[] signatureValue = ecdsaSigner.generateSignature(inputHash);

      return new EcdsaP256SignatureWrapper(signatureValue[0], signatureValue[1]);
   }

   /**
    * Validates message signature
    * 
    * @param toBeSignedDataBytes
    *           bytes of the ToBeSignedData
    * @param signingCertificateBytes
    *           bytes of the certificate which performed the signing
    * @param signingPublicKey
    *           public signing key to use
    * @param signature
    *           wrapped signature to validate
    * @return true if the signature is valid and false otherwise
    */
   public boolean verifySignature(
      byte[] toBeSignedDataBytes,
      byte[] signingCertificateBytes,
      ECPublicKeyParameters signingPublicKey,
      EcdsaP256SignatureWrapper signature) {
      if (toBeSignedDataBytes == null || signingCertificateBytes == null) {
         return false;
      }

      byte[] inputHash = computeDigest(toBeSignedDataBytes, signingCertificateBytes);

      ecdsaSigner.init(false, signingPublicKey);

      return ecdsaSigner.verifySignature(inputHash, signature.getR(), signature.getS());
   }

   /**
    * Computes SHA256 digest of the concatenated toBeSignedDataBytes and signingCertificateBytes 
    * @param toBeSignedDataBytes
    *           bytes of the ToBeSignedData
    * @param signingCertificateBytes
    *           bytes of the certificate which performed the signing
    * @return the SHA256 digest of the concatenated toBeSignedDataBytes and signingCertificateBytes
    */
   public byte[] computeDigest(byte[] toBeSignedDataBytes, byte[] signingCertificateBytes) {
      byte[] tbsBytesHash = cryptoProvider.computeDigest(toBeSignedDataBytes, 0, toBeSignedDataBytes.length);
      byte[] certBytesHash = cryptoProvider.computeDigest(signingCertificateBytes, 0, signingCertificateBytes.length);

      byte[] inputHashConcat = ByteArrayHelper.concat(tbsBytesHash, certBytesHash);
      byte[] inputHash = cryptoProvider.computeDigest(inputHashConcat);
      return inputHash;
   }

   /**
    * Decode 1609.2-2016 EccP256CurvePoint (6.3.23) into Bouncy Castle
    * ECPublicKeyParameters.
    * 
    * @param publicKey
    *           EccP256CurvePoint to decode
    * @return decoded Bouncy Castle ECPublicKeyParameters
    */
   public ECPublicKeyParameters decodePublicKey(EccP256CurvePoint publicKey) {
      if (publicKey == null) {
         log.error("Invalid parameter: publicKey should not be null");
         return null;
      }

      log.debug("Public key type: " + publicKey.getChosenFlag());

      byte[] publicKeyBytes = getPublicKeyBytes(publicKey);

      // The Bouncy Castle ECPublicKeyParameters expects a flag byte at the
      // beginning
      // indicating which compression algorithm, if any, is used for the
      // y-coordinate
      byte publicKeyAlgorithm = (byte) (publicKey.getChosenFlag() - 1);
      publicKeyBytes = ByteArrayHelper.prepend(publicKeyAlgorithm, publicKeyBytes);

      return (!Arrays.areEqual(publicKeyBytes, nullPublicKey))
            ? (new ECPublicKeyParameters(ecdsaEllipticCurve.decodePoint(publicKeyBytes), ecdsaDomainParameters))
            : (null);
   }

   public static byte[] getPublicKeyBytes(EccP256CurvePoint publicKey) {
      byte[] publicKeyBytes = null;
      if (publicKey.hasX_only()) {
         publicKeyBytes = publicKey.getX_only().byteArrayValue();
      } else if (publicKey.hasCompressed_y_0()) {
         publicKeyBytes = publicKey.getCompressed_y_0().byteArrayValue();
      } else if (publicKey.hasCompressed_y_1()) {
         publicKeyBytes = publicKey.getCompressed_y_1().byteArrayValue();
      } else if (publicKey.hasUncompressed()) {
         // Concatenate the uncompressed x & y
         publicKeyBytes = ByteArrayHelper.concat(publicKey.getUncompressed().getX().byteArrayValue(),
            publicKey.getUncompressed().getY().byteArrayValue());
      } else {
         log.error(String.format("Unexpected EccP256CurvePoint Type value %d", publicKey.getChosenFlag()));
      }
      return publicKeyBytes;
   }

   /**
    * Encode BouncyCastlePublicKeyParementers into 1609.2-2016 EccP256CurvePoint
    * (6.3.23)
    * 
    * @param publicKey
    *           ECPublicKeyParameters to encode
    * @return encoded 1609.2-2016 EccP256CurvePoint
    * @throws CryptoException
    *            if encoding fails
    */
   public EccP256CurvePoint encodePublicKey(ECPublicKeyParameters publicKey) throws CryptoException {
      EccP256CurvePoint eccP256CurvePoint;
      if (publicKey != null) {
         ECPoint keyValue = publicKey.getQ();
         BigInteger xValue = keyValue.getAffineXCoord().toBigInteger();
         ECFieldElement yCoord = keyValue.getAffineYCoord();

         OctetString compressedValue = new OctetString(
               EcdsaP256SignatureWrapper.encodeBigInteger(xValue, ECDSAPublicKeyEncodedLength - 1));

         eccP256CurvePoint = (yCoord.testBitZero())
               ? (EccP256CurvePoint.createEccP256CurvePointWithCompressed_y_1(compressedValue))
               : (EccP256CurvePoint.createEccP256CurvePointWithCompressed_y_0(compressedValue));
      } else {
         eccP256CurvePoint = EccP256CurvePoint.createEccP256CurvePointWithFill(new Null());
      }

      return eccP256CurvePoint;
   }

   /**
    * Decodes private key
    * 
    * @param privateKeyBytes
    *           array to decode the key from
    * @return decoded private key
    */
   public ECPrivateKeyParameters decodePrivateKey(byte[] privateKeyBytes) {
      return !Arrays.areEqual(privateKeyBytes, new byte[ECDSAPrivateKeyEncodedLength])
            ? new ECPrivateKeyParameters(new BigInteger(1, privateKeyBytes), ecdsaDomainParameters) : null;
   }

   /**
    * Encodes private key
    * 
    * @param byteBuffer
    *           buffer to encode into
    * @param privateKey
    *           private key to encode
    * @return true if encoding succeeds and false otherwise
    */
   public boolean encodePrivateKey(ByteBuffer byteBuffer, ECPrivateKeyParameters privateKey) {
      byte[] keyBytes;
      if (privateKey != null) {
         keyBytes = privateKey.getD().toByteArray();
         assert (keyBytes != null);
         if (keyBytes.length == ECDSAPrivateKeyEncodedLength) {
            byteBuffer.put(keyBytes);
         } else if (keyBytes.length == ECDSAPrivateKeyEncodedLength + 1) {
            if (keyBytes[0] != (byte) 0) {
               log.error(String.format(
                  "Unexpected key bytes value of length 33.  Expected leading byte value: 0. Actual: 0x%0x.",
                  keyBytes[0]));
               return false;
            }
            byteBuffer.put(keyBytes, 1, ECDSAPrivateKeyEncodedLength);
         } else if (keyBytes.length < ECDSAPrivateKeyEncodedLength) {
            byteBuffer.put(new byte[ECDSAPrivateKeyEncodedLength - keyBytes.length]);
            byteBuffer.put(keyBytes);
         } else {
            log.error(String.format("Unexpected key bytes length: %d.", keyBytes.length));
            return false;
         }
      } else {
         byteBuffer.put(new byte[ECDSAPrivateKeyEncodedLength]);
      }
      return true;
   }

   /**
    * Reconstructs implicit public key
    * 
    * @param issuerCert
    *           issuer certificate used to create the reconstruction value
    * @param certificate
    *           subordinate certificate for which the key is being reconstructed
    * @return reconstructed public key
    * @throws EncodeNotSupportedException
    *            if encoding is not supported
    * @throws EncodeFailedException
    *            if encoding failed
    */
   public ECPublicKeyParameters
         reconstructImplicitPublicKey(CertificateWrapper issuerCert, CertificateWrapper certificate)
               throws EncodeFailedException, EncodeNotSupportedException {

      if (issuerCert == null) {
         log.error("Invalid parameter: Issuer certificate can not be null");
         return null;
      }

      if (certificate == null) {
         log.error("Invalid parameter: Certificate can not be null");
         return null;
      }

      // The operation is QU = e*PU + QCA
      // PU is the reconstruction key of CertU (the subordinate cert)
      // QCA is the public key of the CA
      // e = Hn(CertU).
      // Hn(CertU) is defined in 1609.2-2016 Section 5.3.2 to be:
      // Hash (ToBeSignedCertificate from the subordinate certificate) || Hash
      // (Entirety of issuer certificate)

      // Get PU
      EccP256CurvePoint reconstructionKeyValue = certificate.getCertificate().getToBeSigned().getVerifyKeyIndicator()
            .getReconstructionValue();
      ECPublicKeyParameters PU = decodePublicKey(reconstructionKeyValue);

      // Get e
      CryptoHelper cryptoHelper = new CryptoHelper(cryptoProvider);

      byte[] tbsBytes = Ieee1609dot2Helper.encodeCOER(certificate.getCertificate().getToBeSigned());
      byte[] tbsHash = cryptoHelper.computeDigest(tbsBytes);

      byte[] issuerCertBytes = issuerCert.getBytes();
      byte[] issuerCertHash = cryptoHelper.computeDigest(issuerCertBytes);

      byte[] eInput = ByteArrayHelper.concat(tbsHash, issuerCertHash);
      byte[] eBytes = cryptoHelper.computeDigest(eInput);

      BigInteger e = new BigInteger(1, eBytes);

      // Get QCA
      ECPoint QCA = issuerCert.getSigningPublicKey().getQ();

      // Calculate QU = e*PU + QCA
      ECPoint QU = PU.getQ().multiply(e).add(QCA);

      return new ECPublicKeyParameters(QU, ecdsaDomainParameters);
   }

   /**
    * Reconstructs implicit private key
    * 
    * @param issuerCert
    *           issuer certificate used to create the reconstruction value
    * @param certificate
    *           subordinate certificate for which the key is being reconstructed
    * @param reconstructionKeyValueBytes
    *           bytes of the reconstruction value
    * @param seedPrivateKeyBytes
    *           bytes of the seed private key
    * @return reconstructed private key
    * @throws EncodeNotSupportedException
    *            if encoding is not supported
    * @throws EncodeFailedException
    *            if encoding failed
    */
   public ECPrivateKeyParameters reconstructImplicitPrivateKey(
      CertificateWrapper issuerCert,
      CertificateWrapper certificate,
      byte[] reconstructionKeyValueBytes,
      byte[] seedPrivateKeyBytes) throws EncodeFailedException, EncodeNotSupportedException {

      // The operation is du = r + e*k
      // r is the reconstruction value
      // k is the seed private
      // e = Hn(CertU).
      // Hn(CertU) is defined in 1609.2-2016 Section 5.3.2 to be:
      // Hash (ToBeSignedCertificate from the subordinate certificate) || Hash
      // (Entirety of issuer certificate)

      // Get r
      BigInteger r = new BigInteger(1, reconstructionKeyValueBytes);

      // Get e
      CryptoHelper cryptoHelper = new CryptoHelper(cryptoProvider);

      byte[] tbsBytes = Ieee1609dot2Helper.encodeCOER(certificate.getCertificate().getToBeSigned());
      byte[] tbsHash = cryptoHelper.computeDigest(tbsBytes);

      byte[] issuerCertBytes = issuerCert.getBytes();
      byte[] issuerCertHash = cryptoHelper.computeDigest(issuerCertBytes);

      byte[] eInput = ByteArrayHelper.concat(tbsHash, issuerCertHash);
      byte[] eBytes = cryptoHelper.computeDigest(eInput);

      BigInteger e = new BigInteger(1, eBytes);

      // Get k
      BigInteger k = new BigInteger(seedPrivateKeyBytes);

      // Calculate du = r + e*k
      BigInteger du = r.add(e.multiply(k));

      return new ECPrivateKeyParameters(du, ecdsaDomainParameters);
   }

   /**
    * Generates a asymmetric key pair
    * 
    * @return new asymmetric key pair
    */
   public AsymmetricCipherKeyPair generateKeyPair() {
      return ecdsaKeyGenerator.generateKeyPair();
   }
}
