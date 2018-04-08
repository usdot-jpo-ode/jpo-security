package gov.usdot.cv.security.crypto;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import com.oss.asn1.OctetString;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EccP256CurvePoint;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EciesP256EncryptedKey;
import gov.usdot.cv.security.cert.SecurePrivateKey;
import gov.usdot.cv.security.util.ByteArrayHelper;

/**
 * Helper class that implements encoding and decoding of the
 * EciesP256EncryptedKey (6.3.5)
 */
public class ECIESProvider {

   static private final byte[] derivation = ByteBuffer.allocate(8).putLong(0xdeadbeefcafebabeL).array();
   static private final byte[] encoding = ByteBuffer.allocate(8).putLong(0xebabefacfeebdaedL).array();

   private final ECDSAProvider ecdsaProvider;
   private final CipherParameters iesParameters;
   private final IESEngine iesEngine;
   private Cipher decryptionCipher;

   /**
    * Instantiates ECIES provider with new crypto provider
    * @throws CryptoException 
    */
   public ECIESProvider() throws CryptoException {
      this(new CryptoProvider());
   }

   /**
    * Instantiates ECIES provider with specified cryptographic provider
    * 
    * @param cryptoProvider
    *           cryptographic provider to use
    * @throws CryptoException 
    */
   public ECIESProvider(CryptoProvider cryptoProvider) throws CryptoException {
      this.ecdsaProvider = cryptoProvider.getECDSAProvider();
      iesParameters = new IESWithCipherParameters(derivation, encoding, 128, 128);
      iesEngine = new IESEngine(new ECDHCBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()),
            new Ieee1609dot2Mac1(new SHA256Digest(), 16));
   }

   /**
    * ECIES encrypt symmetric encryption key bytes
    * 
    * @param aesSymmetricEncryptionKeyBytes
    *           symmetric encryption key bytes to encrypt
    * @param ephemeralPrivateKey
    *           ephemeral private key
    * @param recipientEncryptionPublicKey
    *           recipient's asymmetric public key
    * @return encrypted symmetric encryption key bytes
    * @throws InvalidCipherTextException
    *            if encrypting of the symmetric encryption key fails
    */
   public byte[] encrypt(
      byte[] aesSymmetricEncryptionKeyBytes,
      ECPrivateKeyParameters ephemeralPrivateKey,
      ECPublicKeyParameters recipientEncryptionPublicKey) throws InvalidCipherTextException {
      iesEngine.init(true, ephemeralPrivateKey, recipientEncryptionPublicKey, iesParameters);
      return iesEngine.processBlock(aesSymmetricEncryptionKeyBytes, 0, aesSymmetricEncryptionKeyBytes.length);
   }

//   /**
//    * ECIES decrypt encrypted symmetric encryption key and tag bytes
//    * 
//    * @param encryptedKeyAndTag
//    *           encrypted symmetric encryption key and tag bytes to decrypt
//    * @param ephemeralPublicKey
//    *           ephemeral public key
//    * @param recipientECCPrivateKey
//    *           recipient's asymmetric private key
//    * @return decrypted symmetric encryption key bytes
//    * @throws InvalidCipherTextException
//    *            if invalid cipher text
//    */
//   public byte[] decrypt(
//      byte[] encryptedKeyAndTag,
//      ECPublicKeyParameters ephemeralPublicKey,
//      ECPrivateKeyParameters recipientECCPrivateKey) throws InvalidCipherTextException {
//      iesEngine.init(false, recipientECCPrivateKey, ephemeralPublicKey, iesParameters);
//      return iesEngine.processBlock(encryptedKeyAndTag, 0, encryptedKeyAndTag.length);
//   }

   /**
    * @param encryptedSymmetricKeyAndTag
    * @param ephemeralPublicKey
    * @param recipientEnryptionPrivateKey
    * @return
    * @throws NoSuchPaddingException
    * @throws NoSuchAlgorithmException
    * @throws InvalidKeyException
    * @throws InvalidAlgorithmParameterException
    * @throws BadPaddingException
    * @throws IllegalBlockSizeException
    */
   public byte[] decrypt(
      byte[] encryptedSymmetricKeyAndTag,
      ECPublicKeyParameters ephemeralPublicKey,
      SecurePrivateKey recipientEnryptionPrivateKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
         InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

      // Cipher cipher =
      // recipientEnryptionPrivateKeyAlias.getKeyStore().getProvider();
      if (decryptionCipher == null) {
         /*
          * First initialize it as encryption cipher so the algorithm parameter
          * specs are initialized. Then use those parameters to initialize it
          * for decryption.
          */

         decryptionCipher = Cipher.getInstance("ECIES", recipientEnryptionPrivateKey.getKeyStore().getProvider());
         decryptionCipher.init(Cipher.ENCRYPT_MODE, recipientEnryptionPrivateKey.getKey());

         // Initialize it as a decryption cipher
         decryptionCipher.init(Cipher.DECRYPT_MODE, recipientEnryptionPrivateKey.getKey(),
            decryptionCipher.getParameters());
      }

      return decryptionCipher.doFinal(encryptedSymmetricKeyAndTag);
   }

   /**
    * Encodes EciesP256EncryptedKey
    * 
    * @param aesSymmetricEncryptionKey
    *           symmetric encryption key (AES 128 CCM, 16 bytes)
    * @param recipientEncryptionPublicKey
    *           recipient's asymmetric public key
    * @return encoded EciesP256EncryptedKey containing the encrypted key
    * @throws InvalidCipherTextException
    *            if encoding of the symmetric encryption key fails
    * @throws CryptoException
    *            if encoding of the ephemeral public key fails
    */
   public EciesP256EncryptedKey encodeEciesP256EncryptedKey(
      KeyParameter aesSymmetricEncryptionKey,
      ECPublicKeyParameters recipientEncryptionPublicKey) throws InvalidCipherTextException, CryptoException {
      AsymmetricCipherKeyPair ephemeralKeyPair = ecdsaProvider.generateKeyPair();
      ECPublicKeyParameters ephemeralPublicKey = (ECPublicKeyParameters) ephemeralKeyPair.getPublic();
      ECPrivateKeyParameters ephemeralPrivateKey = (ECPrivateKeyParameters) ephemeralKeyPair.getPrivate();

      EccP256CurvePoint v = ecdsaProvider.encodePublicKey(ephemeralPublicKey);

      byte[] encryptedKeyAndTag = encrypt(aesSymmetricEncryptionKey.getKey(), ephemeralPrivateKey,
         recipientEncryptionPublicKey);
      byte[] encryptedSymmectricKey = new byte[AESProvider.keyLength];
      byte[] encryptedTag = new byte[encryptedKeyAndTag.length - AESProvider.keyLength];
      System.arraycopy(encryptedKeyAndTag, 0, encryptedSymmectricKey, 0, encryptedSymmectricKey.length);
      System.arraycopy(encryptedKeyAndTag, AESProvider.keyLength, encryptedTag, 0, encryptedTag.length);
      OctetString c = new OctetString(encryptedSymmectricKey);
      OctetString t = new OctetString(encryptedTag);

      EciesP256EncryptedKey eciesP256EncryptedKey = new EciesP256EncryptedKey(v, c, t);

      return eciesP256EncryptedKey;
   }

//   /**
//    * Decodes EciesP256EncryptedKey
//    * 
//    * @param eciesP256EncryptedKey
//    *           encoded EciesP256EncryptedKey containing the encrypted key
//    * @param recipientEnryptionPrivateKey
//    *           recipient's asymmetric private key or null to skip decryption
//    * @return decrypted symmetric encryption key or null if
//    *         recipientEncryptionPrivateKey is null
//    * @throws InvalidCipherTextException
//    *            if decoding of the symmetric encryption key fails
//    */
//   public KeyParameter decodeEciesP256EncryptedKey(
//      EciesP256EncryptedKey eciesP256EncryptedKey,
//      ECPrivateKeyParameters recipientEnryptionPrivateKey) throws InvalidCipherTextException {
//
//      if (recipientEnryptionPrivateKey == null) {
//         return null;
//      }
//
//      ECPublicKeyParameters ephemeralPublicKey = ecdsaProvider.decodePublicKey(eciesP256EncryptedKey.getV());
//
//      OctetString encryptedSymmectricKey = eciesP256EncryptedKey.getC();
//      OctetString encryptedTag = eciesP256EncryptedKey.getT();
//
//      byte[] encryptedSymmetricKeyAndTag = ByteArrayHelper.concat(encryptedSymmectricKey.byteArrayValue(),
//         encryptedTag.byteArrayValue());
//
//      byte[] aesSymmetricEncryptionKeyBytes = decrypt(encryptedSymmetricKeyAndTag, ephemeralPublicKey,
//         recipientEnryptionPrivateKey);
//
//      return new KeyParameter(aesSymmetricEncryptionKeyBytes);
//   }

   public KeyParameter decodeEciesP256EncryptedKey(
      EciesP256EncryptedKey eciesP256EncryptedKey,
      SecurePrivateKey recipientEnryptionPrivateKey) throws InvalidKeyException, NoSuchAlgorithmException,
         NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
      if (recipientEnryptionPrivateKey == null) {
         return null;
      }

      ECPublicKeyParameters ephemeralPublicKey = ecdsaProvider.decodePublicKey(eciesP256EncryptedKey.getV());

      OctetString encryptedSymmectricKey = eciesP256EncryptedKey.getC();
      OctetString encryptedTag = eciesP256EncryptedKey.getT();

      byte[] encryptedSymmetricKeyAndTag = ByteArrayHelper.concat(encryptedSymmectricKey.byteArrayValue(),
         encryptedTag.byteArrayValue());

      byte[] aesSymmetricEncryptionKeyBytes = decrypt(encryptedSymmetricKeyAndTag, ephemeralPublicKey,
         recipientEnryptionPrivateKey);

      return new KeyParameter(aesSymmetricEncryptionKeyBytes);
   }

}
